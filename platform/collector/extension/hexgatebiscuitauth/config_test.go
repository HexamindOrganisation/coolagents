package hexgatebiscuitauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validConfig() *Config {
	cfg := createDefaultConfig().(*Config)
	cfg.PublicKeyFile = "/etc/hexgate/hexgate.pub"
	cfg.Revocation.DSN = "postgres://hexgate@localhost:5433/hexgate"
	return cfg
}

func TestConfigValidate_happy_path(t *testing.T) {
	require.NoError(t, validConfig().Validate())
}

// Revocation on by default is the security-relevant default: API keys are
// minted with ttl_seconds=None, so signature checks alone would honour a
// leaked key forever.
func TestCreateDefaultConfig_happy_path(t *testing.T) {
	cfg := createDefaultConfig().(*Config)

	assert.True(t, cfg.Revocation.Enabled)
	assert.Equal(t, defaultPollInterval, cfg.Revocation.PollInterval)
	assert.Equal(t, defaultMaxStaleness, cfg.Revocation.MaxStaleness)
	// Requiring the operator to name a key rules out a silently-wrong default.
	assert.Empty(t, cfg.PublicKey)
	assert.Empty(t, cfg.PublicKeyFile)
}

func TestConfigValidate_when_no_public_key_is_set_then_an_error_is_returned(t *testing.T) {
	cfg := validConfig()
	cfg.PublicKeyFile = ""

	err := cfg.Validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "one of public_key or public_key_file is required")
}

func TestConfigValidate_when_both_public_key_forms_are_set_then_an_error_is_returned(t *testing.T) {
	cfg := validConfig()
	cfg.PublicKey = "Zm9v"

	err := cfg.Validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestConfigValidate_when_revocation_is_enabled_without_a_dsn_then_an_error_is_returned(t *testing.T) {
	cfg := validConfig()
	cfg.Revocation.DSN = ""

	err := cfg.Validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "revocation.dsn is required")
}

// Turning revocation off is a supported local-development choice, so it must
// not require the database settings that only matter when it is on.
func TestConfigValidate_when_revocation_is_disabled_then_database_settings_are_not_required(t *testing.T) {
	cfg := validConfig()
	cfg.Revocation = RevocationConfig{Enabled: false}

	require.NoError(t, cfg.Validate())
}

// The committed dev password on a non-local host is always a misconfiguration:
// the repo is readable by anyone, and the devtoken table holds every API key's
// secret. Same tripwire as settings.py's _refuse_dev_password_on_remote_host.
func TestConfigValidate_when_dev_password_points_at_a_remote_host_then_an_error_is_returned(t *testing.T) {
	cfg := validConfig()
	cfg.Revocation.DSN = "postgres://hexgate:hexgate-dev-password@db.staging.internal:5432/hexgate"

	err := cfg.Validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "committed")
	assert.Contains(t, err.Error(), "db.staging.internal")
}

// The committed default DSN has to keep working — the guard exists to protect
// deployments, not to break `make collector-run`.
func TestConfigValidate_when_dev_password_points_at_localhost_then_config_is_accepted(t *testing.T) {
	cfg := validConfig()
	cfg.Revocation.DSN = "postgres://hexgate:hexgate-dev-password@localhost:5433/hexgate"

	require.NoError(t, cfg.Validate())
}

func TestConfigValidate_when_a_real_password_points_at_a_remote_host_then_config_is_accepted(t *testing.T) {
	cfg := validConfig()
	cfg.Revocation.DSN = "postgres://hexgate:s3cret-rotated@db.staging.internal:5432/hexgate"

	require.NoError(t, cfg.Validate())
}

func TestConfigValidate_when_dsn_is_malformed_then_an_error_is_returned(t *testing.T) {
	cfg := validConfig()
	cfg.Revocation.DSN = "not a dsn"

	err := cfg.Validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "revocation.dsn does not parse")
}

func TestConfigValidate_when_poll_interval_is_not_positive_then_an_error_is_returned(t *testing.T) {
	cfg := validConfig()
	cfg.Revocation.PollInterval = 0

	err := cfg.Validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "revocation.poll_interval must be positive")
}

// A max_staleness below the poll interval would make every snapshot stale
// before its replacement could arrive, rejecting all traffic.
func TestConfigValidate_when_max_staleness_is_below_poll_interval_then_an_error_is_returned(t *testing.T) {
	cfg := validConfig()
	cfg.Revocation.PollInterval = time.Minute
	cfg.Revocation.MaxStaleness = 30 * time.Second

	err := cfg.Validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be at least revocation.poll_interval")
}
