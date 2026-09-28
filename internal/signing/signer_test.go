package signing

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"hash/crc32"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/golang-jwt/jwt/v5"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type countingSigner struct {
	local Local
	count atomic.Int64
}

func (s *countingSigner) Sign(ctx context.Context, b []byte) ([]byte, error) {
	s.count.Add(1)
	return s.local.Sign(ctx, b)
}
func TestAppJWTCache(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer := &countingSigner{local: Local{Key: key}}
	app := &AppJWT{Signer: signer, AppID: "123"}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			raw, err := app.Token(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			token, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}))
			if err != nil || !token.Valid {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if signer.count.Load() != 1 {
		t.Fatal("cache stampede")
	}
	app.refresh = time.Now().Add(-time.Second)
	if _, err := app.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if signer.count.Load() != 2 {
		t.Fatal("cache did not refresh")
	}
}

type kmsStub struct {
	alter func(*kmspb.AsymmetricSignResponse)
}

func (s kmsStub) AsymmetricSign(_ context.Context, req *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	if req.DigestCrc32C.Value != int64(crc32.Checksum(req.Digest.GetSha256(), castagnoli)) {
		return nil, errors.New("bad request CRC")
	}
	sig := make([]byte, 256)
	res := &kmspb.AsymmetricSignResponse{Name: req.Name, Signature: sig, SignatureCrc32C: wrapperspb.Int64(int64(crc32.Checksum(sig, castagnoli))), VerifiedDigestCrc32C: true}
	s.alter(res)
	return res, nil
}
func TestKMSIntegrity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*kmspb.AsymmetricSignResponse)
		bad   bool
	}{
		{"valid", func(*kmspb.AsymmetricSignResponse) {}, false}, {"request corrupted", func(r *kmspb.AsymmetricSignResponse) { r.VerifiedDigestCrc32C = false }, true}, {"response corrupted", func(r *kmspb.AsymmetricSignResponse) { r.Signature[0] = 1 }, true}, {"wrong key", func(r *kmspb.AsymmetricSignResponse) { r.Name = "other" }, true}, {"missing checksum", func(r *kmspb.AsymmetricSignResponse) { r.SignatureCrc32C = nil }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := KMS{Client: kmsStub{alter: tc.alter}, Key: "key"}
			_, err := s.Sign(context.Background(), make([]byte, 32))
			if (err != nil) != tc.bad {
				t.Fatal(err)
			}
		})
	}
}

func TestPEMFormats(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, block := range []*pem.Block{{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}, {Type: "PRIVATE KEY", Bytes: pkcs8}} {
		parsed, err := ParsePEM(pem.EncodeToMemory(block))
		if err != nil || parsed.N.Cmp(key.N) != 0 {
			t.Fatal(err)
		}
	}
	for _, bad := range [][]byte{[]byte("not PEM"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkcs8}), append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), []byte("trailing")...)} {
		if _, err := ParsePEM(bad); err == nil {
			t.Fatal("accepted invalid PEM")
		}
	}
}
