package hexgatebiscuitauth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/collector/client"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensionauth"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Metadata keys this extension writes onto the request context.
//
// metadataProjectID is the one config.yaml already depends on twice: the batch
// processor lists it in `metadata_keys` so the context survives batching, and
// the kafka exporter reads it via `message_key_from_metadata_key` to keep a
// tenant's spans on one partition.
const (
	metadataProjectID = "project_id"
	metadataTokenID   = "token_id"

	authorizationHeader = "authorization"
	bearerScheme        = "bearer"

	// maxCredentialLength bounds the Authorization value before anything is
	// decoded, parsed, or verified. Everything downstream costs work
	// proportional to the token's size — base64 decode, protobuf parse, and
	// one Ed25519 verification plus one Datalog run per block — and
	// attenuation needs no signing key, so a token's size is attacker-chosen.
	// A minted key is a few hundred bytes and legitimate attenuation adds
	// ~150 per block, so 8 KiB is far above anything real.
	maxCredentialLength = 8 << 10
)

// Reasons returned to the caller. These become the body of a 401 (HTTP) or the
// gRPC status message, so they say what to fix and nothing more — anything
// about our own internal state stays in the logs.
var (
	errMissingCredential   = errors.New("missing bearer credential")
	errInvalidCredential   = errors.New("invalid Hexgate API key")
	errAmbiguousCredential = errors.New("more than one bearer credential supplied")
	errUnavailable         = &unavailableError{}
)

// unavailableError is "our side is broken, retry", as opposed to "your key is
// bad". GRPCStatus() is what makes the difference reach the client: configgrpc
// forwards an error's own status when it carries one, so gRPC callers get
// UNAVAILABLE — which OTLP SDK exporters treat as retryable — instead of a
// terminal UNAUTHENTICATED during a control-plane outage. HTTP has no
// equivalent hook (confighttp hardcodes 401 for every auth error), so HTTP
// callers must go by the message.
type unavailableError struct{}

func (*unavailableError) Error() string { return "cannot verify credentials right now" }

func (e *unavailableError) GRPCStatus() *status.Status {
	return status.New(codes.Unavailable, e.Error())
}

type biscuitAuth struct {
	cfg    *Config
	logger *zap.Logger

	rootPub ed25519.PublicKey
	cache   *revocationCache
}

var (
	_ extension.Extension  = (*biscuitAuth)(nil)
	_ extensionauth.Server = (*biscuitAuth)(nil)
)

func (a *biscuitAuth) Start(ctx context.Context, _ component.Host) error {
	rootPub, err := loadRootPublicKey(a.cfg)
	if err != nil {
		return err
	}
	a.rootPub = rootPub

	if !a.cfg.Revocation.Enabled {
		a.logger.Warn("revocation checking is disabled: this Collector will accept any " +
			"correctly-signed API key, including revoked ones. API keys are minted without " +
			"a TTL, so a leaked key stays valid indefinitely. Do not run this way outside " +
			"local development.")
		return nil
	}

	pool, err := pgxpool.New(ctx, string(a.cfg.Revocation.DSN))
	if err != nil {
		return fmt.Errorf("connect to the control-plane database: %w", err)
	}
	a.cache = newRevocationCache(&postgresKeySource{pool: pool}, a.cfg.Revocation, a.logger)
	if err := a.cache.start(ctx); err != nil {
		pool.Close()
		a.cache = nil
		return err
	}
	return nil
}

func (a *biscuitAuth) Shutdown(context.Context) error {
	if a.cache != nil {
		a.cache.shutdown()
	}
	return nil
}

// Authenticate verifies the request's API key and returns a context carrying
// the project the spans belong to.
//
// `sources` is the request's headers (HTTP) or call metadata (gRPC); the
// framework normalises both into this one map, which is why nothing here is
// protocol-specific.
func (a *biscuitAuth) Authenticate(ctx context.Context, sources map[string][]string) (context.Context, error) {
	credential, err := bearerCredential(sources)
	if err != nil {
		return ctx, err
	}
	if len(credential) > maxCredentialLength {
		a.logger.Debug("rejected an oversized credential", zap.Int("length", len(credential)))
		return ctx, errInvalidCredential
	}

	_, envelopeProjectID, biscuitB64, err := parseEnvelope(credential)
	if err != nil {
		a.logger.Debug("rejected a malformed API key envelope", zap.Error(err))
		return ctx, errInvalidCredential
	}

	id, err := verifyBiscuit(a.rootPub, biscuitB64, time.Now())
	if err != nil {
		// Debug, not Warn: a bad signature is normally a misconfigured client
		// or a stale key, and at ingest volumes this would be a log flood.
		a.logger.Debug("rejected an API key that failed verification",
			zap.String("envelope_project_id", envelopeProjectID), zap.Error(err))
		return ctx, errInvalidCredential
	}

	projectID, err := a.resolveProject(id)
	if err != nil {
		return ctx, err
	}

	return withIdentity(ctx, projectID, id), nil
}

// resolveProject turns a verified token into the project that currently owns
// it, consulting the revocation cache when it is enabled.
func (a *biscuitAuth) resolveProject(id *identity) (string, error) {
	if a.cache == nil {
		// Revocation disabled: the signed fact is all we have. Start() has
		// already warned about running this way.
		if id.ProjectID == "" {
			// The platform always mints a project fact, so a token without one
			// is not ours — and with no row to fall back to, stamping it would
			// hand the pipeline an empty partition key.
			a.logger.Warn("rejected a validly-signed token that carries no project fact",
				zap.String("token_id", id.TokenID))
			return "", errInvalidCredential
		}
		return id.ProjectID, nil
	}

	projectID, err := a.cache.lookup(id.TokenID)
	switch {
	case errors.Is(err, errUnknownAPIKey):
		// Worth a Warn even at volume: this is the signature of a key that
		// was revoked, or one minted before PR #126 made the signed token_id
		// the row's own id. The latter needs re-minting and is otherwise
		// indistinguishable from a revocation, so name both.
		a.logger.Warn("rejected an API key whose token_id matches no row in devtoken: "+
			"it was revoked, or it predates the token_id/row-id fix and must be re-minted",
			zap.String("token_id", id.TokenID),
			zap.String("token_project_id", id.ProjectID))
		return "", errInvalidCredential
	case errors.Is(err, errCacheStale), errors.Is(err, errCacheNotLoaded):
		// Not the caller's fault, and not their business either — the detail
		// goes to the log, the caller gets "try again".
		a.logger.Error("refusing traffic because the revocation list cannot be trusted",
			zap.Error(err))
		return "", errUnavailable
	case err != nil:
		a.logger.Error("unexpected failure resolving an API key", zap.Error(err))
		return "", errUnavailable
	}

	// Signed fact vs. live row. The signature rules out tampering, so a
	// mismatch means the key was moved between projects after it was minted;
	// the row wins and the divergence is worth seeing.
	if id.ProjectID != "" && id.ProjectID != projectID {
		a.logger.Warn("API key's signed project fact disagrees with its current row; using the row",
			zap.String("token_id", id.TokenID),
			zap.String("token_project_id", id.ProjectID),
			zap.String("row_project_id", projectID))
	}
	return projectID, nil
}

// bearerCredential finds the Authorization value in the request.
//
// HTTP hands us http.Header's canonical casing ("Authorization") and gRPC hands
// us metadata.MD's lowercase ("authorization"), so this matches
// case-insensitively rather than guessing which protocol it is serving.
//
// Exactly one credential is accepted. http.Header and metadata.MD both collapse
// a repeated header into one key with several values, so more than one can only
// come from something unusual upstream; picking a winner would make the choice
// depend on that upstream's normalization, so ambiguity is rejected instead.
func bearerCredential(sources map[string][]string) (string, error) {
	var credentials []string
	for name, values := range sources {
		if !strings.EqualFold(name, authorizationHeader) {
			continue
		}
		for _, value := range values {
			if credential := stripBearerScheme(value); credential != "" {
				credentials = append(credentials, credential)
			}
		}
	}
	switch len(credentials) {
	case 0:
		return "", errMissingCredential
	case 1:
		return credentials[0], nil
	default:
		return "", errAmbiguousCredential
	}
}

// stripBearerScheme returns the credential from an Authorization value, or ""
// if there is none.
//
// The scheme is optional: the SDK sends "Bearer <envelope>", but a bare
// envelope is accepted so a hand-rolled curl still works. The prefix has to be
// matched before trimming the whole value, or "Bearer   " collapses to
// "Bearer" and gets mistaken for the credential itself.
func stripBearerScheme(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < len(bearerScheme) || !strings.EqualFold(value[:len(bearerScheme)], bearerScheme) {
		return value
	}
	rest := value[len(bearerScheme):]
	// Only a scheme if a separator follows. Without this check a credential
	// that merely started with those letters would be truncated.
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		return value
	}
	return strings.TrimSpace(rest)
}

// withIdentity attaches the resolved project to the request context.
//
// The receiver's own interceptor has already populated client.Info by the time
// an authenticator runs — confighttp wraps clientInfoHandler outside the auth
// interceptor, and configgrpc chains client info first, with a comment saying
// so — which is why this reads the existing metadata and adds to it rather
// than replacing it.
func withIdentity(ctx context.Context, projectID string, id *identity) context.Context {
	info := client.FromContext(ctx)

	metadata := make(map[string][]string)
	for key := range info.Metadata.Keys() {
		// Drop the credential at the auth boundary. With include_metadata on,
		// the receiver copies every header into the metadata that travels down
		// the pipeline; the API key has no business going any further.
		if strings.EqualFold(key, authorizationHeader) {
			continue
		}
		metadata[key] = info.Metadata.Get(key)
	}
	metadata[metadataProjectID] = []string{projectID}
	metadata[metadataTokenID] = []string{id.TokenID}

	info.Metadata = client.NewMetadata(metadata)
	info.Auth = &authData{projectID: projectID, id: id}
	return client.NewContext(ctx, info)
}

// authData exposes the token's facts to downstream components through
// client.Info.Auth, which is the conventional place for them. project_id is
// the resolved one, not the token's own claim.
type authData struct {
	projectID string
	id        *identity
}

var _ client.AuthData = (*authData)(nil)

func (a *authData) GetAttribute(name string) any {
	switch name {
	case "project_id":
		return a.projectID
	case "token_id":
		return a.id.TokenID
	case "name":
		return a.id.Name
	case "env":
		return a.id.Env
	case "scopes":
		return a.id.Scopes
	case "issued_at":
		return a.id.IssuedAt
	default:
		return nil
	}
}

func (a *authData) GetAttributeNames() []string {
	return []string{"project_id", "token_id", "name", "env", "scopes", "issued_at"}
}
