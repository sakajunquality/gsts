// gsts exchanges workload identity for narrowly scoped GitHub installation tokens.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/sakajunquality/gsts/internal/config"
	"github.com/sakajunquality/gsts/internal/github"
	"github.com/sakajunquality/gsts/internal/kmsimport"
	"github.com/sakajunquality/gsts/internal/oidc"
	"github.com/sakajunquality/gsts/internal/server"
	"github.com/sakajunquality/gsts/internal/signing"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("gsts stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) == 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println(version)
		return nil
	}
	if len(os.Args) == 2 && (os.Args[1] == "--help" || os.Args[1] == "help") {
		fmt.Println("Usage: gsts serve | kms-import <CryptoKey> <PEM file> | version")
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) == 4 && os.Args[1] == "kms-import" {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		b, err := os.ReadFile(os.Args[3])
		if err != nil {
			return err
		}
		defer clear(b)
		client, err := kms.NewKeyManagementClient(ctx)
		if err != nil {
			return err
		}
		defer client.Close()
		name, err := kmsimport.Import(ctx, client, os.Args[2], b)
		if err != nil {
			return err
		}
		fmt.Println(name)
		return nil
	}
	if len(os.Args) != 2 || os.Args[1] != "serve" {
		return errors.New("usage: gsts serve | kms-import <CryptoKey> <PEM file> | version")
	}
	c, err := config.Load()
	if err != nil {
		return err
	}
	opts := &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.LevelKey {
			a.Key = "severity"
		}
		return a
	}}
	var handler slog.Handler = slog.NewJSONHandler(os.Stdout, opts)
	if c.LogFormat == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	log := slog.New(handler)
	slog.SetDefault(log)
	var signer signing.DigestSigner
	if c.KeySource == "kms" {
		client, err := kms.NewKeyManagementClient(ctx)
		if err != nil {
			return err
		}
		defer client.Close()
		signer = &signing.KMS{Client: client, Key: c.KMSKey}
	} else {
		var b []byte
		if c.KeySource == "file" {
			b, err = os.ReadFile(c.KeyFile)
		} else {
			b = []byte(os.Getenv(c.KeyEnv))
		}
		if err != nil {
			return err
		}
		key, err := signing.ParsePEM(b)
		clear(b)
		if err != nil {
			return err
		}
		signer = &signing.Local{Key: key}
		log.Warn("insecure_local_signing_enabled")
	}
	app := &signing.AppJWT{Signer: signer, AppID: c.AppID}
	gh := github.New(c.GitHubURL)
	// Best effort: a fresh import-only key may not have a version yet. Listen
	// regardless; /healthz reports signing readiness and recovers after import.
	setupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	var appPermissions map[string]string
	if token, e := app.Token(setupCtx); e == nil {
		appPermissions, e = gh.AppPermissions(setupCtx, token)
		if e != nil {
			log.Warn("app_permissions_unavailable", "error", e)
		}
	} else {
		log.Warn("signer_not_ready", "error", e)
	}
	cancel()
	s := &server.Server{Config: c, Verifier: oidc.New(c.AllowedIssuers), Signer: app, GitHub: gh, Log: log, AppPermissions: appPermissions}
	httpServer := &http.Server{Addr: ":" + c.Port, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768}
	result := make(chan error, 1)
	go func() { result <- httpServer.ListenAndServe() }()
	log.Info("server_started", "port", c.Port, "version", version)
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 55*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdown)
	}
}
