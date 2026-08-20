package hexgatebiscuitauth

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/client"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newTestAuth builds an extension already "started": root key loaded and a
// revocation snapshot in place, without touching the filesystem or Postgres.
func newTestAuth(t *testing.T, rootPub ed25519.PublicKey, keys map[string]string) *biscuitAuth {
	t.Helper()
	now := time.Now()
	return &biscuitAuth{
		cfg:     createDefaultConfig().(*Config),
		logger:  zap.NewNop(),
		rootPub: rootPub,
		cache:   newLoadedCache(keys, now, now),
	}
}

func envelopeFor(biscuitB64 string) string {
	return "fty_live_support-bot_" + biscuitB64
}

// httpSources mimics what confighttp passes in: http.Header's canonical casing.
func httpSources(credential string) map[string][]string {
	return map[string][]string{"Authorization": {credential}}
}

// grpcSources mimics what configgrpc passes in: metadata.MD is always lowercase.
func grpcSources(credential string) map[string][]string {
	return map[string][]string{"authorization": {credential}}
}

func TestAuthenticate_happy_path(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	auth := newTestAuth(t, pub, map[string]string{opts.tokenID: opts.projectID})
	token := envelopeFor(mintToken(t, priv, opts))

	ctx, err := auth.Authenticate(context.Background(), httpSources("Bearer "+token))

	require.NoError(t, err)
	info := client.FromContext(ctx)
	assert.Equal(t, []string{opts.projectID}, info.Metadata.Get(metadataProjectID))
	assert.Equal(t, []string{opts.tokenID}, info.Metadata.Get(metadataTokenID))
	require.NotNil(t, info.Auth)
	assert.Equal(t, opts.projectID, info.Auth.GetAttribute("project_id"))
	assert.Equal(t, opts.name, info.Auth.GetAttribute("name"))
	assert.Equal(t, opts.scopes, info.Auth.GetAttribute("scopes"))
}

// The credential arrives under a different key depending on the protocol, and
// one extension serves both.
func TestAuthenticate_when_credential_arrives_as_lowercase_grpc_metadata_then_it_is_found(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	auth := newTestAuth(t, pub, map[string]string{opts.tokenID: opts.projectID})
	token := envelopeFor(mintToken(t, priv, opts))

	ctx, err := auth.Authenticate(context.Background(), grpcSources("Bearer "+token))

	require.NoError(t, err)
	assert.Equal(t, []string{opts.projectID}, client.FromContext(ctx).Metadata.Get(metadataProjectID))
}

func TestAuthenticate_when_scheme_is_omitted_then_the_bare_envelope_is_accepted(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	auth := newTestAuth(t, pub, map[string]string{opts.tokenID: opts.projectID})

	ctx, err := auth.Authenticate(context.Background(), httpSources(envelopeFor(mintToken(t, priv, opts))))

	require.NoError(t, err)
	assert.Equal(t, []string{opts.projectID}, client.FromContext(ctx).Metadata.Get(metadataProjectID))
}

// include_metadata copies every request header into the metadata that travels
// down the pipeline. The API key must not be part of that.
func TestAuthenticate_when_metadata_is_propagated_then_the_credential_is_stripped(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	auth := newTestAuth(t, pub, map[string]string{opts.tokenID: opts.projectID})
	token := envelopeFor(mintToken(t, priv, opts))

	incoming := client.NewContext(context.Background(), client.Info{
		Metadata: client.NewMetadata(map[string][]string{
			"Authorization": {"Bearer " + token},
			"X-Tenant-Hint": {"acme"},
		}),
	})

	ctx, err := auth.Authenticate(incoming, httpSources("Bearer "+token))

	require.NoError(t, err)
	info := client.FromContext(ctx)
	assert.Empty(t, info.Metadata.Get("Authorization"), "the API key must not travel past the auth boundary")
	assert.Empty(t, info.Metadata.Get("authorization"))
	// Unrelated metadata the receiver collected has to survive.
	assert.Equal(t, []string{"acme"}, info.Metadata.Get("X-Tenant-Hint"))
}

// The length cap runs before the envelope is even split, so an oversized
// credential is rejected without any decoding or signature work.
func TestAuthenticate_when_credential_is_oversized_then_the_request_is_rejected(t *testing.T) {
	pub, _ := newTestKeypair(t)
	auth := newTestAuth(t, pub, nil)
	oversized := envelopeFor(strings.Repeat("A", maxCredentialLength))

	_, err := auth.Authenticate(context.Background(), httpSources("Bearer "+oversized))

	require.ErrorIs(t, err, errInvalidCredential)
}

func TestAuthenticate_when_no_authorization_header_is_present_then_the_request_is_rejected(t *testing.T) {
	pub, _ := newTestKeypair(t)
	auth := newTestAuth(t, pub, nil)

	_, err := auth.Authenticate(context.Background(), map[string][]string{"X-Other": {"value"}})

	require.ErrorIs(t, err, errMissingCredential)
}

func TestAuthenticate_when_credential_is_empty_then_the_request_is_rejected(t *testing.T) {
	pub, _ := newTestKeypair(t)
	auth := newTestAuth(t, pub, nil)

	_, err := auth.Authenticate(context.Background(), httpSources("Bearer   "))

	require.ErrorIs(t, err, errMissingCredential)
}

// http.Header and metadata.MD both collapse a repeated header into one key, so
// two credentials can only come from something unusual upstream; picking a
// winner would let that upstream decide which one authenticates.
func TestAuthenticate_when_two_credentials_are_supplied_then_the_request_is_rejected(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	auth := newTestAuth(t, pub, map[string]string{opts.tokenID: opts.projectID})
	token := envelopeFor(mintToken(t, priv, opts))

	_, err := auth.Authenticate(context.Background(), map[string][]string{
		"Authorization": {"Bearer " + token, "Bearer fty_live_other_bm90aGluZw=="},
	})

	require.ErrorIs(t, err, errAmbiguousCredential,
		"one of the two being valid must not rescue an ambiguous request")
}

func TestAuthenticate_when_envelope_is_malformed_then_the_request_is_rejected(t *testing.T) {
	pub, _ := newTestKeypair(t)
	auth := newTestAuth(t, pub, nil)

	_, err := auth.Authenticate(context.Background(), httpSources("Bearer not-an-envelope"))

	require.ErrorIs(t, err, errInvalidCredential)
}

func TestAuthenticate_when_token_is_signed_by_another_key_then_the_request_is_rejected(t *testing.T) {
	pub, _ := newTestKeypair(t)
	_, otherPriv := newTestKeypair(t)
	opts := defaultMintOptions()
	auth := newTestAuth(t, pub, map[string]string{opts.tokenID: opts.projectID})

	_, err := auth.Authenticate(context.Background(),
		httpSources("Bearer "+envelopeFor(mintToken(t, otherPriv, opts))))

	require.ErrorIs(t, err, errInvalidCredential)
}

// A revoked key's row is gone, so its token_id resolves to nothing. This is
// also what a key minted before the token_id/row-id fix looks like.
func TestAuthenticate_when_token_id_matches_no_row_then_the_request_is_rejected(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	auth := newTestAuth(t, pub, map[string]string{"tok_someoneelse": "other-project"})

	_, err := auth.Authenticate(context.Background(),
		httpSources("Bearer "+envelopeFor(mintToken(t, priv, opts))))

	require.ErrorIs(t, err, errInvalidCredential)
}

// The caller gets "try again", not our internal state — and crucially not an
// accepted request.
func TestAuthenticate_when_revocation_snapshot_is_stale_then_the_request_is_refused_as_unavailable(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	auth := newTestAuth(t, pub, map[string]string{opts.tokenID: opts.projectID})
	now := time.Now()
	auth.cache = newLoadedCache(
		map[string]string{opts.tokenID: opts.projectID},
		now.Add(-time.Hour), now)

	_, err := auth.Authenticate(context.Background(),
		httpSources("Bearer "+envelopeFor(mintToken(t, priv, opts))))

	require.ErrorIs(t, err, errUnavailable)
	assert.NotContains(t, err.Error(), "max_staleness", "internal state must stay out of the client's error")
	// configgrpc forwards an error's own status, so this is what makes gRPC
	// clients see a retryable UNAVAILABLE instead of a terminal
	// UNAUTHENTICATED during a control-plane outage.
	s, ok := status.FromError(err)
	require.True(t, ok, "errUnavailable must carry a gRPC status")
	assert.Equal(t, codes.Unavailable, s.Code())
}

// The outage log must not scale with request volume: at ingest rates a
// per-request Error would flood the log during the very incident it describes.
func TestAuthenticate_when_the_cache_stays_stale_then_the_outage_is_logged_once(t *testing.T) {
	core, observed := observer.New(zap.ErrorLevel)
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	auth := newTestAuth(t, pub, map[string]string{opts.tokenID: opts.projectID})
	auth.logger = zap.New(core)
	now := time.Now()
	auth.cache = newLoadedCache(map[string]string{opts.tokenID: opts.projectID}, now.Add(-time.Hour), now)
	sources := httpSources("Bearer " + envelopeFor(mintToken(t, priv, opts)))

	for range 5 {
		_, err := auth.Authenticate(context.Background(), sources)
		require.ErrorIs(t, err, errUnavailable)
	}

	assert.Equal(t, 1, observed.Len(), "five rejected requests must produce one Error, not five")
}

// The trust boundary: the row is live state, the signed fact is a mint-time
// snapshot, so the row wins when a key has been moved between projects.
func TestAuthenticate_when_row_project_differs_from_the_signed_fact_then_the_row_wins(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	opts.projectID = "project-at-mint-time"
	auth := newTestAuth(t, pub, map[string]string{opts.tokenID: "project-right-now"})

	ctx, err := auth.Authenticate(context.Background(),
		httpSources("Bearer "+envelopeFor(mintToken(t, priv, opts))))

	require.NoError(t, err)
	assert.Equal(t, []string{"project-right-now"},
		client.FromContext(ctx).Metadata.Get(metadataProjectID))
}

// The envelope's project segment is unsigned — it exists only to make a leaked
// key greppable — so it must never reach the pipeline.
func TestAuthenticate_when_envelope_project_disagrees_with_the_token_then_the_envelope_is_ignored(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	auth := newTestAuth(t, pub, map[string]string{opts.tokenID: opts.projectID})
	tampered := "fty_live_attacker-project_" + mintToken(t, priv, opts)

	ctx, err := auth.Authenticate(context.Background(), httpSources("Bearer "+tampered))

	require.NoError(t, err)
	assert.Equal(t, []string{opts.projectID},
		client.FromContext(ctx).Metadata.Get(metadataProjectID))
}

// With revocation off there is no row to consult, so the signed fact is all
// that is left. Start() warns loudly about running this way.
func TestAuthenticate_when_revocation_is_disabled_then_the_signed_project_fact_is_used(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	auth := newTestAuth(t, pub, nil)
	auth.cache = nil

	ctx, err := auth.Authenticate(context.Background(),
		httpSources("Bearer "+envelopeFor(mintToken(t, priv, opts))))

	require.NoError(t, err)
	assert.Equal(t, []string{opts.projectID},
		client.FromContext(ctx).Metadata.Get(metadataProjectID))
}

// With revocation off there is no row to fall back to, and stamping the empty
// claim would hand the pipeline an empty partition key.
func TestAuthenticate_when_revocation_is_disabled_and_the_token_has_no_project_fact_then_the_request_is_rejected(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	opts.omitProject = true
	auth := newTestAuth(t, pub, nil)
	auth.cache = nil

	_, err := auth.Authenticate(context.Background(),
		httpSources("Bearer "+envelopeFor(mintToken(t, priv, opts))))

	require.ErrorIs(t, err, errInvalidCredential)
}

func TestAuthenticate_when_token_ttl_has_expired_then_the_request_is_rejected(t *testing.T) {
	pub, priv := newTestKeypair(t)
	opts := defaultMintOptions()
	opts.issuedAt = time.Now().Add(-2 * time.Hour)
	opts.ttl = time.Hour
	auth := newTestAuth(t, pub, map[string]string{opts.tokenID: opts.projectID})

	_, err := auth.Authenticate(context.Background(),
		httpSources("Bearer "+envelopeFor(mintToken(t, priv, opts))))

	require.ErrorIs(t, err, errInvalidCredential)
}

func TestStart_when_the_public_key_cannot_be_loaded_then_start_returns_an_error(t *testing.T) {
	auth := &biscuitAuth{
		cfg:    &Config{PublicKeyFile: "/nonexistent/hexgate.pub"},
		logger: zap.NewNop(),
	}

	err := auth.Start(context.Background(), nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "read public_key_file")
}

func TestStripBearerScheme_happy_path(t *testing.T) {
	assert.Equal(t, "fty_live_proj_abc", stripBearerScheme("Bearer fty_live_proj_abc"))
}

func TestStripBearerScheme_when_scheme_casing_varies_then_it_is_still_stripped(t *testing.T) {
	for _, value := range []string{"bearer fty_x", "BEARER fty_x", "BeArEr fty_x"} {
		assert.Equal(t, "fty_x", stripBearerScheme(value), value)
	}
}

func TestStripBearerScheme_when_there_is_no_scheme_then_the_value_is_returned_whole(t *testing.T) {
	assert.Equal(t, "fty_live_proj_abc", stripBearerScheme("  fty_live_proj_abc  "))
}

// "Bearer" with nothing after it carries no credential; returning the scheme
// word itself would surface as a confusing "malformed envelope" instead.
func TestStripBearerScheme_when_only_the_scheme_is_present_then_it_is_empty(t *testing.T) {
	assert.Empty(t, stripBearerScheme("Bearer"))
	assert.Empty(t, stripBearerScheme("Bearer   "))
	assert.Empty(t, stripBearerScheme(""))
}

// A credential that merely begins with those letters must not be truncated.
func TestStripBearerScheme_when_value_only_starts_with_the_scheme_letters_then_it_is_untouched(t *testing.T) {
	assert.Equal(t, "bearerish-token", stripBearerScheme("bearerish-token"))
}
