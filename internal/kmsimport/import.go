// Package kmsimport imports a GitHub-generated RSA key into an import-only KMS key.
package kmsimport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"github.com/sakajunquality/gsts/internal/signing"
	"github.com/tink-crypto/tink-go/v2/kwp/subtle"
)

var keyName = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`)

// Wrap implements KMS RSA_OAEP_3072_SHA256_AES_256 using Tink's RFC 5649 KWP.
func Wrap(public *rsa.PublicKey, der []byte) ([]byte, error) {
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}
	defer clear(aesKey)
	wrappedAES, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, public, aesKey, nil)
	if err != nil {
		return nil, err
	}
	kwp, err := subtle.NewKWP(aesKey)
	if err != nil {
		return nil, err
	}
	wrappedDER, err := kwp.Wrap(der)
	if err != nil {
		return nil, err
	}
	return append(wrappedAES, wrappedDER...), nil
}

type Client interface {
	GetCryptoKey(context.Context, *kmspb.GetCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
	CreateImportJob(context.Context, *kmspb.CreateImportJobRequest, ...gax.CallOption) (*kmspb.ImportJob, error)
	GetImportJob(context.Context, *kmspb.GetImportJobRequest, ...gax.CallOption) (*kmspb.ImportJob, error)
	ImportCryptoKeyVersion(context.Context, *kmspb.ImportCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	GetCryptoKeyVersion(context.Context, *kmspb.GetCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
}

var _ Client = (*kms.KeyManagementClient)(nil)

func Import(ctx context.Context, client Client, name string, keyPEM []byte) (string, error) {
	if !keyName.MatchString(name) {
		return "", errors.New("expected CryptoKey resource name (without version)")
	}
	key, err := signing.ParsePEM(keyPEM)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	defer clear(der)
	target, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: name})
	if err != nil {
		return "", err
	}
	if !target.ImportOnly || target.Purpose != kmspb.CryptoKey_ASYMMETRIC_SIGN || target.VersionTemplate == nil || target.VersionTemplate.Algorithm != kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256 {
		return "", errors.New("target must be import-only ASYMMETRIC_SIGN / RSA_SIGN_PKCS1_2048_SHA256")
	}
	random := make([]byte, 8)
	if _, err = rand.Read(random); err != nil {
		return "", err
	}
	parent, _, _ := strings.Cut(name, "/cryptoKeys/")
	job, err := client.CreateImportJob(ctx, &kmspb.CreateImportJobRequest{Parent: parent, ImportJobId: "gsts-" + hex.EncodeToString(random), ImportJob: &kmspb.ImportJob{ImportMethod: kmspb.ImportJob_RSA_OAEP_3072_SHA256_AES_256, ProtectionLevel: target.VersionTemplate.ProtectionLevel}})
	if err != nil {
		return "", err
	}
	for job.State != kmspb.ImportJob_ACTIVE {
		if job.State != kmspb.ImportJob_PENDING_GENERATION {
			return "", fmt.Errorf("import job state %s", job.State)
		}
		if err = wait(ctx); err != nil {
			return "", err
		}
		job, err = client.GetImportJob(ctx, &kmspb.GetImportJobRequest{Name: job.Name})
		if err != nil {
			return "", err
		}
	}
	if job.PublicKey == nil {
		return "", errors.New("import job missing public key")
	}
	block, _ := pem.Decode([]byte(job.PublicKey.Pem))
	if block == nil {
		return "", errors.New("invalid wrapping public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok || public.N.BitLen() != 3072 {
		return "", errors.New("expected RSA 3072 wrapping key")
	}
	wrapped, err := Wrap(public, der)
	if err != nil {
		return "", err
	}
	version, err := client.ImportCryptoKeyVersion(ctx, &kmspb.ImportCryptoKeyVersionRequest{Parent: name, Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, ImportJob: job.Name, WrappedKey: wrapped})
	if err != nil {
		return "", err
	}
	for version.State != kmspb.CryptoKeyVersion_ENABLED {
		if version.State != kmspb.CryptoKeyVersion_PENDING_IMPORT {
			return "", fmt.Errorf("imported version %s state %s", version.Name, version.State)
		}
		if err = wait(ctx); err != nil {
			return "", fmt.Errorf("import submitted as %s: %w", version.Name, err)
		}
		version, err = client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: version.Name})
		if err != nil {
			return "", err
		}
	}
	return version.Name, nil
}
func wait(ctx context.Context) error {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
