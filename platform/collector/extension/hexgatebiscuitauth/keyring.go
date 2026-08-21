package hexgatebiscuitauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// loadRootPublicKey resolves the platform's root Ed25519 public key from
// whichever of the two config forms was supplied. Validate() has already
// guaranteed exactly one of them is set.
func loadRootPublicKey(cfg *Config) (ed25519.PublicKey, error) {
	if cfg.PublicKeyFile != "" {
		raw, err := os.ReadFile(cfg.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read public_key_file %q: %w", cfg.PublicKeyFile, err)
		}
		key, err := parsePublicKey(raw)
		if err != nil {
			return nil, fmt.Errorf("public_key_file %q: %w", cfg.PublicKeyFile, err)
		}
		return key, nil
	}
	key, err := parsePublicKey([]byte(cfg.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("public_key: %w", err)
	}
	return key, nil
}

// parsePublicKey accepts the two shapes the platform hands out the same key in:
// the raw 32 bytes that core/keystore.py writes to `hexgate.pub`, or the
// base64 text that `GET /v1/.well-known/keys` publishes as `keys[0].x`
// (base64url, unpadded, 43 characters).
//
// A raw key is detected by length. That is unambiguous in practice: no
// base64 encoding of a 32-byte key is 32 characters long (they are 43 or 44),
// so the two forms cannot be confused for each other.
func parsePublicKey(raw []byte) (ed25519.PublicKey, error) {
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}

	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, errors.New("empty public key")
	}

	// The JWKS form is unpadded base64url; the others are accepted so an
	// operator who pastes a padded or standard-alphabet copy is not stuck
	// debugging a decode error.
	var decoded []byte
	var decodeErr error
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		decoded, decodeErr = enc.DecodeString(text)
		if decodeErr == nil {
			break
		}
	}
	if decodeErr != nil {
		return nil, fmt.Errorf(
			"expected either %d raw bytes or a base64-encoded key, got %d bytes that do not decode: %w",
			ed25519.PublicKeySize, len(text), decodeErr)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"an Ed25519 public key is %d bytes, but this one decodes to %d",
			ed25519.PublicKeySize, len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}
