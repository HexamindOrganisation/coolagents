package hexgatebiscuitauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	biscuit "github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/stretchr/testify/require"
)

// datalogDatetime mirrors core/biscuits.py:_datalog_datetime so tokens minted
// here carry the same literal format the platform mints.
func datalogDatetime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05Z")
}

// mintOptions describes a token to build. Defaults mirror what
// tokens/service.py:mint_api_key produces: every fact set, and no TTL.
type mintOptions struct {
	projectID string
	tokenID   string
	name      string
	env       string
	scopes    []string
	issuedAt  time.Time
	// ttl, when non-zero, adds the same `check if time($t), $t < <expiry>`
	// caveat core/biscuits.py:mint_token writes for an expiring token.
	ttl time.Duration
	// omitTokenID drops the token_id fact, to exercise the rejection path.
	omitTokenID bool
	// omitProject drops the project fact, which the platform always mints;
	// with revocation disabled there is no row to fall back to.
	omitProject bool
	// extraFacts are appended to the authority block verbatim.
	extraFacts []string
}

func defaultMintOptions() mintOptions {
	return mintOptions{
		projectID: "support-bot",
		tokenID:   "tok_a1b2c3d4e5f6",
		name:      "ci-deploy",
		env:       "live",
		scopes:    []string{"mint_user_token", "read_audit"},
		issuedAt:  time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC),
	}
}

// mintToken builds a Biscuit shaped exactly like the ones the platform mints,
// signed by the given key, and returns its base64 payload.
//
// Minting in Go keeps these tests hermetic. The cross-language guarantee — that
// biscuit-go accepts what biscuit-python signs — is covered separately by
// TestVerifyBiscuit_when_token_was_minted_by_the_python_platform_then_it_verifies,
// which runs against a committed fixture.
func mintToken(t *testing.T, priv ed25519.PrivateKey, opts mintOptions) string {
	t.Helper()

	builder := biscuit.NewBuilder(priv)

	var facts []string
	if !opts.omitProject {
		facts = append(facts, fmt.Sprintf(`project("%s")`, opts.projectID))
	}
	facts = append(facts,
		fmt.Sprintf(`name("%s")`, opts.name),
		fmt.Sprintf(`env("%s")`, opts.env),
		fmt.Sprintf(`issued_at(%s)`, datalogDatetime(opts.issuedAt)),
	)
	if !opts.omitTokenID {
		facts = append(facts, fmt.Sprintf(`token_id("%s")`, opts.tokenID))
	}
	for _, scope := range opts.scopes {
		facts = append(facts, fmt.Sprintf(`scope("%s")`, scope))
	}
	facts = append(facts, opts.extraFacts...)

	for _, source := range facts {
		fact, err := parser.FromStringFact(source)
		require.NoError(t, err, "parse fact %q", source)
		require.NoError(t, builder.AddAuthorityFact(fact))
	}

	if opts.ttl != 0 {
		expiry := datalogDatetime(opts.issuedAt.Add(opts.ttl))
		check, err := parser.FromStringCheck(fmt.Sprintf("check if time($t), $t < %s", expiry))
		require.NoError(t, err)
		require.NoError(t, builder.AddAuthorityCheck(check))
	}

	token, err := builder.Build()
	require.NoError(t, err)
	return serialize(t, token)
}

// attenuate appends a block to an already-minted token, the way
// core/biscuits.py:attenuate_token does. No signing key is needed, which is
// precisely why appended facts must never be trusted.
func attenuate(t *testing.T, biscuitB64 string, blockSource string) string {
	t.Helper()

	raw, err := base64.URLEncoding.DecodeString(biscuitB64)
	require.NoError(t, err)
	token, err := biscuit.Unmarshal(raw)
	require.NoError(t, err)

	block, err := parser.FromStringBlock(blockSource)
	require.NoError(t, err)

	builder := token.CreateBlock()
	require.NoError(t, builder.AddBlock(block))

	attenuated, err := token.Append(rand.Reader, builder.Build())
	require.NoError(t, err)
	return serialize(t, attenuated)
}

func serialize(t *testing.T, token *biscuit.Biscuit) string {
	t.Helper()
	raw, err := token.Serialize()
	require.NoError(t, err)
	// biscuit-python's to_base64() is URL-safe with padding; match it.
	return base64.URLEncoding.EncodeToString(raw)
}

func newTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

// appendedBlockCode returns the Datalog source of a token's appended blocks.
// Biscuit.Code() and BlockCount() both cover b.blocks only — the authority
// block lives in b.authority — so this is the attenuation, not the whole token.
func appendedBlockCode(t *testing.T, biscuitB64 string) []string {
	t.Helper()

	raw, err := base64.URLEncoding.DecodeString(biscuitB64)
	require.NoError(t, err)
	token, err := biscuit.Unmarshal(raw)
	require.NoError(t, err)
	require.Equal(t, token.BlockCount(), len(token.Code()))
	return token.Code()
}
