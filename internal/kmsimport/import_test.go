package kmsimport

import (
	"bytes"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"github.com/googleapis/gax-go/v2"
	"testing"

	"github.com/tink-crypto/tink-go/v2/kwp/subtle"
)

func TestWrappingRoundTrip(t *testing.T) {
	wrapping, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := Wrap(&wrapping.PublicKey, der)
	if err != nil {
		t.Fatal(err)
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, wrapping, wrapped[:384], nil)
	if err != nil {
		t.Fatal(err)
	}
	kwp, err := subtle.NewKWP(aesKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := kwp.Unwrap(wrapped[384:])
	if err != nil || !bytes.Equal(got, der) {
		t.Fatalf("round trip: %v", err)
	}
	wrapped[len(wrapped)-1] ^= 1
	if _, err := kwp.Unwrap(wrapped[384:]); err == nil {
		t.Fatal("corruption accepted")
	}
}
func TestOpenSSLKWPVector(t *testing.T) {
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	kwp, err := subtle.NewKWP(decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := kwp.Wrap(decode("c37b7e6492584340bed12207808941155068f738"))
	if err != nil {
		t.Fatal(err)
	}
	want := decode("29b7fa191c2165684374eee9f74595e2a42bace75c425b3053efa26ffe1bb32f")
	if !bytes.Equal(got, want) {
		t.Fatalf("OpenSSL vector mismatch: %x", got)
	}
}

type importStub struct {
	wrapping   *rsa.PrivateKey
	expected   []byte
	imported   bool
	importOnly bool
	t          *testing.T
}

func (s *importStub) GetCryptoKey(context.Context, *kmspb.GetCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error) {
	return &kmspb.CryptoKey{ImportOnly: s.importOnly, Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN, VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}}, nil
}
func (s *importStub) CreateImportJob(_ context.Context, req *kmspb.CreateImportJobRequest, _ ...gax.CallOption) (*kmspb.ImportJob, error) {
	if req.Parent != "projects/p/locations/r/keyRings/k" || req.ImportJob.ImportMethod != kmspb.ImportJob_RSA_OAEP_3072_SHA256_AES_256 || req.ImportJob.ProtectionLevel != kmspb.ProtectionLevel_SOFTWARE {
		s.t.Fatal(req)
	}
	der, err := x509.MarshalPKIXPublicKey(&s.wrapping.PublicKey)
	if err != nil {
		s.t.Fatal(err)
	}
	return &kmspb.ImportJob{Name: req.Parent + "/importJobs/job", State: kmspb.ImportJob_ACTIVE, PublicKey: &kmspb.ImportJob_WrappingPublicKey{Pem: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}}, nil
}
func (s *importStub) GetImportJob(context.Context, *kmspb.GetImportJobRequest, ...gax.CallOption) (*kmspb.ImportJob, error) {
	return nil, errors.New("unexpected poll")
}
func (s *importStub) ImportCryptoKeyVersion(_ context.Context, req *kmspb.ImportCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	if req.Algorithm != kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256 || req.Parent != "projects/p/locations/r/keyRings/k/cryptoKeys/key" || req.ImportJob != "projects/p/locations/r/keyRings/k/importJobs/job" {
		s.t.Fatal(req)
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.wrapping, req.WrappedKey[:384], nil)
	if err != nil {
		s.t.Fatal(err)
	}
	kwp, err := subtle.NewKWP(aesKey)
	if err != nil {
		s.t.Fatal(err)
	}
	plain, err := kwp.Unwrap(req.WrappedKey[384:])
	if err != nil || !bytes.Equal(plain, s.expected) {
		s.t.Fatal("imported material mismatch", err)
	}
	s.imported = true
	return &kmspb.CryptoKeyVersion{Name: req.Parent + "/cryptoKeyVersions/1", State: kmspb.CryptoKeyVersion_ENABLED}, nil
}
func (s *importStub) GetCryptoKeyVersion(context.Context, *kmspb.GetCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	return nil, errors.New("unexpected version poll")
}
func TestImport(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrapping, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	stub := &importStub{wrapping: wrapping, expected: expected, importOnly: true, t: t}
	name := "projects/p/locations/r/keyRings/k/cryptoKeys/key"
	version, err := Import(context.Background(), stub, name, keyPEM)
	if err != nil || version != name+"/cryptoKeyVersions/1" || !stub.imported {
		t.Fatal(version, err)
	}
	stub.importOnly = false
	stub.imported = false
	if _, err := Import(context.Background(), stub, name, keyPEM); err == nil || stub.imported {
		t.Fatal("imported to unsafe target")
	}
	if _, err := Import(context.Background(), stub, name+"/cryptoKeyVersions/1", keyPEM); err == nil {
		t.Fatal("accepted version as target")
	}
}
