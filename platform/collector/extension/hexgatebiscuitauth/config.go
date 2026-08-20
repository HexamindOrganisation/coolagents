// Package hexgatebiscuitauth authenticates incoming OTLP requests that carry a
// Hexgate API key, and hands the rest of the pipeline the project the spans
// belong to.
//
// It replaces the scaffold's stock `bearertokenauth` placeholder. An API key is
// a Biscuit (https://www.biscuitsec.org/) minted by the control plane's root
// Ed25519 key — see platform/api/hexgate_api/core/biscuits.py — wrapped in the
// envelope `fty_<env>_<project>_<biscuit_b64>`.
//
// Per request, in order:
//
//  1. pull the credential out of the request (HTTP `Authorization` header or
//     gRPC call metadata — the auth-extension framework hands us both as one
//     map, so there is no protocol-specific parsing here);
//  2. split the envelope and base64-decode the Biscuit;
//  3. verify the Ed25519 signature chain against the platform's root public
//     key;
//  4. run the Datalog authorizer, which enforces whatever checks the token
//     carries (e.g. a TTL caveat);
//  5. read the authority block's facts — `token_id`, `project`, `env`, `name`,
//     `scope`, `issued_at`;
//  6. resolve `token_id` against the revocation cache, which is where the
//     authoritative `project_id` comes from;
//  7. stamp `project_id` and `token_id` onto the request's client metadata.
//
// Steps 1-5 are stateless and do no I/O. Step 6 reads an in-process snapshot
// refreshed on a timer, so it does no per-request I/O either.
//
// Step 7 is what the rest of config.yaml is already waiting on: the batch
// processor forwards `project_id` via its `metadata_keys`, and the kafka
// exporter uses it as the partition key through
// `message_key_from_metadata_key`.
package hexgatebiscuitauth

import (
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/config/configopaque"
)

// Defaults for the revocation cache. The 15-30s poll window comes from the
// design doc; 20s sits in the middle of it.
const (
	defaultPollInterval = 20 * time.Second
	defaultMaxStaleness = 2 * time.Minute
)

// Config is the `hexgatebiscuitauth` block in config.yaml.
type Config struct {
	// PublicKeyFile points at the platform's public key on disk — the
	// `hexgate.pub` that core/keystore.py writes next to the private half
	// (0644, raw 32 bytes). Mutually exclusive with PublicKey.
	PublicKeyFile string `mapstructure:"public_key_file"`

	// PublicKey is the same key inline, base64-encoded — the exact string
	// `GET /v1/.well-known/keys` publishes as `keys[0].x`. Handy when the
	// Collector has no shared filesystem with the control plane.
	PublicKey string `mapstructure:"public_key"`

	Revocation RevocationConfig `mapstructure:"revocation"`
}

// RevocationConfig controls the in-process cache of live API keys.
//
// Revoking a key deletes its row (see tokens/service.py:delete_api_key), so
// "revoked" means "no longer in the table" — a lookup miss, not a flag.
type RevocationConfig struct {
	// Enabled turns the revocation check on. Defaults to true: a Collector
	// that only checks signatures would honour a leaked API key forever,
	// since keys are minted with no TTL (tokens/service.py passes
	// ttl_seconds=None).
	Enabled bool `mapstructure:"enabled"`

	// DSN is the control plane's Postgres, e.g.
	// postgres://hexgate:...@localhost:5433/hexgate. Read-only access to the
	// `devtoken` table is all this needs.
	DSN configopaque.String `mapstructure:"dsn"`

	// PollInterval is how often the whole key table is re-read. This is also
	// the worst-case window in which an already-revoked key still works.
	PollInterval time.Duration `mapstructure:"poll_interval"`

	// MaxStaleness is how long a snapshot may go un-refreshed before the
	// extension stops trusting it and rejects every request. Without this,
	// a Postgres outage would silently freeze the revocation list and
	// revoked keys would keep working indefinitely.
	MaxStaleness time.Duration `mapstructure:"max_staleness"`
}

func (c *Config) Validate() error {
	switch {
	case c.PublicKey == "" && c.PublicKeyFile == "":
		return errors.New("one of public_key or public_key_file is required (the platform's root Ed25519 public key)")
	case c.PublicKey != "" && c.PublicKeyFile != "":
		return errors.New("public_key and public_key_file are mutually exclusive")
	}

	if !c.Revocation.Enabled {
		return nil
	}
	if c.Revocation.DSN == "" {
		return errors.New("revocation.dsn is required while revocation.enabled is true; " +
			"set revocation.enabled: false to run on signature and TTL checks alone")
	}
	if c.Revocation.PollInterval <= 0 {
		return fmt.Errorf("revocation.poll_interval must be positive, got %s", c.Revocation.PollInterval)
	}
	if c.Revocation.MaxStaleness < c.Revocation.PollInterval {
		return fmt.Errorf(
			"revocation.max_staleness (%s) must be at least revocation.poll_interval (%s), "+
				"otherwise every snapshot is stale on arrival",
			c.Revocation.MaxStaleness, c.Revocation.PollInterval)
	}
	return nil
}
