//go:build integration

package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The property the whole partitioning strategy rests on: project_id, resolved
// by the auth extension from the API key's row, reaches Redpanda as the record
// key. Three separate settings have to agree for that — the metadata key the
// extension writes, the batch processor's metadata_keys, and the kafka
// exporter's message_key_from_metadata_key — and a break in any one of them is
// silent, costing only partition locality rather than raising an error.
func TestCollectorPipeline_happy_path(t *testing.T) {
	pool := connectPostgres(t)
	private, publicKeyFile := writeRootKeypair(t)
	topic := "hexgate.otlp.itest." + randomHex(t, 6)
	createTopic(t, topic)

	fixture := seedAPIKey(t, pool, "placeholder")
	envelope := mintEnvelope(t, private, fixture)

	collector := startCollector(t, collectorOptions{
		publicKeyFile: publicKeyFile,
		topic:         topic,
		pollInterval:  testPollInterval,
		maxStaleness:  testMaxStaleness,
	})

	status, body := postSpans(t, collector, envelope)
	require.Equal(t, http.StatusOK, status, "body: %s", body)

	record := consumeOne(t, topic, 30*time.Second)
	assert.Equal(t, fixture.projectID, string(record.Key),
		"the record key must be the project_id resolved from the key's row")
	assert.NotEmpty(t, record.Value, "the record should carry the OTLP payload")
}

// Revocation deletes the row, so the Collector only learns about it on its next
// poll. This pins both halves: that it still works before the poll, and that it
// stops afterwards.
func TestCollectorPipeline_when_api_key_is_revoked_then_spans_are_rejected_after_the_next_poll(t *testing.T) {
	pool := connectPostgres(t)
	private, publicKeyFile := writeRootKeypair(t)
	topic := "hexgate.otlp.itest." + randomHex(t, 6)
	createTopic(t, topic)

	fixture := seedAPIKey(t, pool, "placeholder")
	envelope := mintEnvelope(t, private, fixture)

	collector := startCollector(t, collectorOptions{
		publicKeyFile: publicKeyFile,
		topic:         topic,
		pollInterval:  testPollInterval,
		maxStaleness:  testMaxStaleness,
	})

	status, body := postSpans(t, collector, envelope)
	require.Equal(t, http.StatusOK, status, "the key should work before revocation; body: %s", body)

	revokeAPIKey(t, pool, fixture.tokenID)

	// Poll rather than sleeping for exactly one interval: the refresh lands
	// somewhere inside the next tick, not at a predictable offset from here.
	// tryPostSpans, not postSpans: a FailNow from Eventually's condition
	// goroutine is unreliable, and a transient transport blip should be a
	// retry here, not a test death.
	require.Eventually(t, func() bool {
		status, _, err := tryPostSpans(collector, envelope)
		return err == nil && status == http.StatusUnauthorized
	}, 10*testPollInterval, testPollInterval/4,
		"a revoked key must stop being accepted once the revocation cache refreshes")
}

// A key that verifies cryptographically but matches no row must be refused.
// This is also what a key minted before the signed token_id became the row id
// looks like, which is why the Collector logs that case distinctly.
func TestCollectorPipeline_when_token_id_matches_no_row_then_request_is_rejected(t *testing.T) {
	connectPostgres(t)
	private, publicKeyFile := writeRootKeypair(t)
	topic := "hexgate.otlp.itest." + randomHex(t, 6)
	createTopic(t, topic)

	// Deliberately never seeded: correctly signed, unknown to the database.
	unseeded := apiKeyFixture{projectID: randomUUID(t), tokenID: "tok_" + randomHex(t, 6)}
	envelope := mintEnvelope(t, private, unseeded)

	collector := startCollector(t, collectorOptions{
		publicKeyFile: publicKeyFile,
		topic:         topic,
		pollInterval:  testPollInterval,
		maxStaleness:  testMaxStaleness,
	})

	status, body := postSpans(t, collector, envelope)

	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Contains(t, body, "invalid Hexgate API key")
	// A rejected request must not reach the exporter at all.
	expectNoRecord(t, topic, 5*time.Second)
}

// A token signed by a key that is not the platform's must be refused even when
// its facts name a project and a key id that do exist.
func TestCollectorPipeline_when_token_is_signed_by_another_key_then_request_is_rejected(t *testing.T) {
	pool := connectPostgres(t)
	_, publicKeyFile := writeRootKeypair(t)
	imposterPrivate, _ := writeRootKeypair(t)
	topic := "hexgate.otlp.itest." + randomHex(t, 6)
	createTopic(t, topic)

	fixture := seedAPIKey(t, pool, "placeholder")
	forged := mintEnvelope(t, imposterPrivate, fixture)

	collector := startCollector(t, collectorOptions{
		publicKeyFile: publicKeyFile,
		topic:         topic,
		pollInterval:  testPollInterval,
		maxStaleness:  testMaxStaleness,
	})

	status, body := postSpans(t, collector, forged)

	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Contains(t, body, "invalid Hexgate API key")
	expectNoRecord(t, topic, 5*time.Second)
}

func TestCollectorPipeline_when_no_credential_is_supplied_then_request_is_rejected(t *testing.T) {
	connectPostgres(t)
	_, publicKeyFile := writeRootKeypair(t)
	topic := "hexgate.otlp.itest." + randomHex(t, 6)
	createTopic(t, topic)

	collector := startCollector(t, collectorOptions{
		publicKeyFile: publicKeyFile,
		topic:         topic,
		pollInterval:  testPollInterval,
		maxStaleness:  testMaxStaleness,
	})

	status, body := postSpans(t, collector, "")

	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Contains(t, body, "missing bearer credential")
}
