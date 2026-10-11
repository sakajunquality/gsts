// Package signing creates cached GitHub App JWTs without exporting KMS keys.
package signing

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"hash/crc32"
	"sync"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type DigestSigner interface {
	Sign(context.Context, []byte) ([]byte, error)
}
type KMSClient interface {
	AsymmetricSign(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}
type KMS struct {
	Client KMSClient
	Key    string
}

var _ KMSClient = (*kms.KeyManagementClient)(nil)
var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func (s *KMS) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	res, err := s.Client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: s.Key, Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}}, DigestCrc32C: wrapperspb.Int64(int64(crc32.Checksum(digest, castagnoli)))})
	if err != nil {
		return nil, err
	}
	if res.Name != s.Key || !res.VerifiedDigestCrc32C || res.SignatureCrc32C == nil || int64(crc32.Checksum(res.Signature, castagnoli)) != res.SignatureCrc32C.Value || len(res.Signature) != 256 {
		return nil, errors.New("KMS signature integrity or algorithm check failed")
	}
	return res.Signature, nil
}

type Local struct{ Key *rsa.PrivateKey }

func ParsePEM(b []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(b)
	if block == nil || len(rest) != 0 {
		return nil, errors.New("expected one PEM private key")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		key, ok = k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("RSA key required")
		}
	default:
		return nil, errors.New("unencrypted RSA private key required")
	}
	if key.N.BitLen() != 2048 {
		return nil, errors.New("RSA 2048-bit key required")
	}
	return key, key.Validate()
}
func (s *Local) Sign(_ context.Context, digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, s.Key, crypto.SHA256, digest)
}

type AppJWT struct {
	Signer  DigestSigner
	AppID   string
	mu      sync.Mutex
	token   string
	refresh time.Time
}

func (a *AppJWT) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if a.token != "" && now.Before(a.refresh) {
		return a.token, nil
	}
	token, err := a.FreshToken(ctx)
	if err != nil {
		return "", err
	}
	a.token = token
	a.refresh = now.Add(8 * time.Minute)
	return token, nil
}

// FreshToken signs a new JWT without reading or changing the exchange cache.
// Readiness uses this to exercise the signer even when Token has a cached JWT.
func (a *AppJWT) FreshToken(ctx context.Context) (string, error) {
	now := time.Now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	// Backdate iat by 60s; exp stays at most ten minutes ahead of wall time.
	body, err := json.Marshal(map[string]any{"iss": a.AppID, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix()})
	if err != nil {
		return "", err
	}
	unsigned := header + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := a.Signer.Sign(ctx, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
