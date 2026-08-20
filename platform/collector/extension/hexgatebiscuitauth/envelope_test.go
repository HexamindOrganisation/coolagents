package hexgatebiscuitauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEnvelope_happy_path(t *testing.T) {
	env, projectID, payload, err := parseEnvelope("fty_live_support-bot_Ch0KAggBEg")

	require.NoError(t, err)
	assert.Equal(t, "live", env)
	assert.Equal(t, "support-bot", projectID)
	assert.Equal(t, "Ch0KAggBEg", payload)
}

// The Biscuit payload is URL-safe base64, so it contains underscores of its
// own; only the first three separators may be treated as delimiters.
func TestParseEnvelope_when_payload_contains_underscores_then_payload_is_kept_whole(t *testing.T) {
	env, projectID, payload, err := parseEnvelope("fty_test_proj_abc_def_ghi")

	require.NoError(t, err)
	assert.Equal(t, "test", env)
	assert.Equal(t, "proj", projectID)
	assert.Equal(t, "abc_def_ghi", payload)
}

func TestParseEnvelope_when_prefix_is_not_fty_then_an_error_is_returned(t *testing.T) {
	_, _, _, err := parseEnvelope("sk_live_support-bot_payload")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed Hexgate token envelope")
}

func TestParseEnvelope_when_segments_are_missing_then_an_error_is_returned(t *testing.T) {
	_, _, _, err := parseEnvelope("fty_live_support-bot")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed Hexgate token envelope")
}

func TestParseEnvelope_when_payload_is_empty_then_an_error_is_returned(t *testing.T) {
	_, _, _, err := parseEnvelope("fty_live_support-bot_")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty biscuit payload")
}
