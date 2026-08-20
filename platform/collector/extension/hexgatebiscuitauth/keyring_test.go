package hexgatebiscuitauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePublicKey_happy_path(t *testing.T) {
	pub, _ := newTestKeypair(t)

	parsed, err := parsePublicKey(pub)

	require.NoError(t, err)
	assert.Equal(t, ed25519.PublicKey(pub), parsed)
}

// The form GET /v1/.well-known/keys publishes as keys[0].x: base64url, no
// padding.
func TestParsePublicKey_when_key_is_unpadded_base64url_then_it_is_decoded(t *testing.T) {
	pub, _ := newTestKeypair(t)

	parsed, err := parsePublicKey([]byte(base64.RawURLEncoding.EncodeToString(pub)))

	require.NoError(t, err)
	assert.Equal(t, ed25519.PublicKey(pub), parsed)
}

func TestParsePublicKey_when_key_has_surrounding_whitespace_then_it_is_decoded(t *testing.T) {
	pub, _ := newTestKeypair(t)

	parsed, err := parsePublicKey([]byte("  " + base64.RawURLEncoding.EncodeToString(pub) + "\n"))

	require.NoError(t, err)
	assert.Equal(t, ed25519.PublicKey(pub), parsed)
}

func TestParsePublicKey_when_key_decodes_to_the_wrong_length_then_an_error_is_returned(t *testing.T) {
	_, err := parsePublicKey([]byte(base64.RawURLEncoding.EncodeToString([]byte("too short"))))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "is 32 bytes")
}

func TestParsePublicKey_when_key_is_empty_then_an_error_is_returned(t *testing.T) {
	_, err := parsePublicKey(nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty public key")
}

// core/keystore.py writes hexgate.pub as the raw 32 bytes, so that is the shape
// public_key_file has to handle without any decoding.
func TestLoadRootPublicKey_happy_path(t *testing.T) {
	pub, _ := newTestKeypair(t)
	path := filepath.Join(t.TempDir(), "hexgate.pub")
	require.NoError(t, os.WriteFile(path, pub, 0o644))

	parsed, err := loadRootPublicKey(&Config{PublicKeyFile: path})

	require.NoError(t, err)
	assert.Equal(t, ed25519.PublicKey(pub), parsed)
}

func TestLoadRootPublicKey_when_file_is_missing_then_an_error_is_returned(t *testing.T) {
	_, err := loadRootPublicKey(&Config{PublicKeyFile: filepath.Join(t.TempDir(), "absent.pub")})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "read public_key_file")
}

func TestLoadRootPublicKey_when_key_is_inline_then_it_is_decoded(t *testing.T) {
	pub, _ := newTestKeypair(t)

	parsed, err := loadRootPublicKey(&Config{PublicKey: base64.RawURLEncoding.EncodeToString(pub)})

	require.NoError(t, err)
	assert.Equal(t, ed25519.PublicKey(pub), parsed)
}
