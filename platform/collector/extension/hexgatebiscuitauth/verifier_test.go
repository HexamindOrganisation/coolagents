package hexgatebiscuitauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var referenceNow = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

func TestVerifyBiscuit_happy_path(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()

	id, err := verifyBiscuit(pub, mintToken(t, priv, opts), referenceNow)

	require.NoError(t, err)
	assert.Equal(t, opts.tokenID, id.TokenID)
	assert.Equal(t, opts.projectID, id.ProjectID)
	assert.Equal(t, opts.env, id.Env)
	assert.Equal(t, opts.name, id.Name)
	assert.ElementsMatch(t, opts.scopes, id.Scopes)
	assert.Equal(t, opts.issuedAt, id.IssuedAt.UTC())
}

func TestVerifyBiscuit_when_signed_by_a_different_key_then_verification_fails(t *testing.T) {
	_, priv := newTestKeypair(t)
	otherPub, _ := newTestKeypair(t)

	_, err := verifyBiscuit(otherPub, mintToken(t, priv, defaultMintOptions()), referenceNow)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

// Guards against the spike's own worry: that a "verified" result is really a
// no-op. A single flipped byte in the key must break it.
func TestVerifyBiscuit_when_public_key_is_corrupted_then_verification_fails(t *testing.T) {
	pub, priv := newTestKeypair(t)
	token := mintToken(t, priv, defaultMintOptions())

	corrupted := make([]byte, len(pub))
	copy(corrupted, pub)
	corrupted[0] ^= 0x01

	_, err := verifyBiscuit(corrupted, token, referenceNow)

	require.Error(t, err)
}

func TestVerifyBiscuit_when_ttl_has_not_expired_then_token_is_accepted(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	opts.issuedAt = referenceNow
	opts.ttl = time.Hour

	id, err := verifyBiscuit(pub, mintToken(t, priv, opts), referenceNow.Add(30*time.Minute))

	require.NoError(t, err)
	assert.Equal(t, opts.tokenID, id.TokenID)
}

func TestVerifyBiscuit_when_ttl_has_expired_then_authorization_fails(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	opts.issuedAt = referenceNow
	opts.ttl = time.Hour

	_, err := verifyBiscuit(pub, mintToken(t, priv, opts), referenceNow.Add(2*time.Hour))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorization failed")
}

// The security property the whole design leans on. attenuate_token needs no
// secret, so anyone holding a token can append blocks to it; if a forged
// token_id in an appended block could win, the revocation lookup — and with it
// the project the spans are billed and isolated under — would be
// attacker-controlled.
func TestVerifyBiscuit_when_an_appended_block_forges_facts_then_authority_facts_win(t *testing.T) {
	pub, priv := newTestKeypair(t)
	token := mintToken(t, priv, defaultMintOptions())

	forged := attenuate(t, token, `token_id("tok_forged000"); project("victim-project");`)

	// Non-vacuity: assert the forged facts really did land in an appended
	// block, so this test cannot quietly stop exercising the attack. Code()
	// and BlockCount() cover appended blocks only — the authority block is
	// held separately — so seeing exactly one here is the attenuation.
	appended := appendedBlockCode(t, forged)
	require.Len(t, appended, 1, "attenuation must have added exactly one block")
	require.Contains(t, appended[0], "tok_forged000", "the forged fact must be in the appended block")

	id, err := verifyBiscuit(pub, forged, referenceNow)

	require.NoError(t, err, "an attenuated token is still validly signed and must verify")
	assert.Equal(t, "tok_a1b2c3d4e5f6", id.TokenID, "token_id must come from the authority block")
	assert.Equal(t, "support-bot", id.ProjectID, "project must come from the authority block")
}

// Attenuation is legitimate as well as abusable: a narrowing check appended by
// a dev's backend must still be enforced.
func TestVerifyBiscuit_when_an_appended_block_adds_a_failing_check_then_authorization_fails(t *testing.T) {
	pub, priv := newTestKeypair(t)
	token := mintToken(t, priv, defaultMintOptions())

	narrowed := attenuate(t, token, `check if user("alice");`)

	_, err := verifyBiscuit(pub, narrowed, referenceNow)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorization failed")
}

func TestVerifyBiscuit_when_token_id_fact_is_missing_then_verification_fails(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	opts.omitTokenID = true

	_, err := verifyBiscuit(pub, mintToken(t, priv, opts), referenceNow)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one token_id")
}

// Two token_id facts would make the revocation lookup ambiguous, so it is
// rejected rather than resolved by picking one.
func TestVerifyBiscuit_when_authority_block_has_two_token_ids_then_verification_fails(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	opts.extraFacts = []string{`token_id("tok_second00000")`}

	_, err := verifyBiscuit(pub, mintToken(t, priv, opts), referenceNow)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one token_id")
}

func TestVerifyBiscuit_when_payload_is_not_base64_then_verification_fails(t *testing.T) {
	pub, _ := newTestKeypair(t)

	_, err := verifyBiscuit(pub, "not-valid-base64!!!", referenceNow)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "URL-safe base64")
}

func TestVerifyBiscuit_when_payload_is_base64_but_not_a_biscuit_then_verification_fails(t *testing.T) {
	pub, _ := newTestKeypair(t)

	_, err := verifyBiscuit(pub, "aGVsbG8gd29ybGQ=", referenceNow)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "deserialize biscuit")
}

// Padding is the character most likely to be lost copying a key around, so the
// unpadded form has to verify too.
func TestVerifyBiscuit_when_payload_padding_is_stripped_then_token_is_accepted(t *testing.T) {
	pub, priv := newTestKeypair(t)
	token := mintToken(t, priv, defaultMintOptions())

	stripped := token
	for len(stripped) > 0 && stripped[len(stripped)-1] == '=' {
		stripped = stripped[:len(stripped)-1]
	}
	require.NotEqual(t, token, stripped, "fixture must actually have had padding to strip")

	id, err := verifyBiscuit(pub, stripped, referenceNow)

	require.NoError(t, err)
	assert.Equal(t, "tok_a1b2c3d4e5f6", id.TokenID)
}
