//go:build integration

// Package integration exercises the built hexgate-collector binary against a
// real Postgres and a real Redpanda.
//
// It covers the two properties the extension's own unit tests structurally
// cannot reach, because both live in the wiring rather than in the code:
//
//   - project_id, set on the request context by the auth extension, survives
//     the batch processor and arrives as the Kafka record's key. That depends
//     on the batch processor's `metadata_keys` and the kafka exporter's
//     `message_key_from_metadata_key` agreeing with the metadata key the
//     extension actually writes. Nothing in a unit test spans all three.
//   - revoking a key stops traffic once the cache polls, against a real table
//     and a real timer.
//
// These are opt-in (`-tags integration`), the same shape as the Python side's
// `pytest -m integration`, so `make collector-check` stays hermetic. Run them
// with `make collector-test-integration`, which starts the infrastructure and
// creates the schema first.
//
// Tests here fail rather than skip when the infrastructure is missing: opting
// in with the build tag is a statement that you want them run, and a suite
// that silently skips is worse than one that is honestly red.
package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	biscuit "github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

const (
	// Defaults match platform/docker-compose.yml's published ports. LOCAL DEV
	// ONLY credentials, same as everywhere else in this repo.
	defaultPostgresDSN = "postgres://hexgate:hexgate-dev-password@localhost:5433/hexgate"
	defaultBroker      = "localhost:9092"

	// Short enough to keep the revocation test quick, long enough that a
	// refresh is not racing the assertions.
	testPollInterval = 2 * time.Second
	testMaxStaleness = 5 * time.Minute
)

func postgresDSN() string {
	if dsn := os.Getenv("HEXGATE_COLLECTOR_POSTGRES_DSN"); dsn != "" {
		return dsn
	}
	return defaultPostgresDSN
}

func broker() string {
	if b := os.Getenv("HEXGATE_REDPANDA_BOOTSTRAP_SERVER"); b != "" {
		return b
	}
	return defaultBroker
}

// collectorDir is the directory holding the binary and config.yaml. Tests run
// the collector with this as its working directory so the relative
// public_key_file default in config.yaml resolves the way it does in dev.
func collectorDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("..")
	require.NoError(t, err)
	return dir
}

func binaryPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(collectorDir(t), "hexgate-collector")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("collector binary not found at %s: %v\n"+
			"Build it first: make collector-check", path, err)
	}
	return path
}

// ---------------------------------------------------------------------------
// Postgres
// ---------------------------------------------------------------------------

func connectPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), postgresDSN())
	require.NoError(t, err, "build a Postgres pool for %s", postgresDSN())
	t.Cleanup(pool.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("cannot reach Postgres at %s: %v\nStart it with: make postgres-up", postgresDSN(), err)
	}

	// The tables are the Python side's to create; this suite only reads and
	// writes rows. A missing table means the control plane has never run
	// against this database.
	var exists bool
	err = pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'devtoken')`,
	).Scan(&exists)
	require.NoError(t, err)
	if !exists {
		t.Fatal("the devtoken table does not exist in this database.\n" +
			"Create the schema once with: make collector-test-integration (or make platform-api-pg)")
	}
	return pool
}

// apiKeyFixture is one org/project/api-key chain, the minimum the devtoken
// foreign keys require.
type apiKeyFixture struct {
	orgID     string
	projectID string
	tokenID   string
}

// seedAPIKey inserts the rows an API key needs to resolve, and removes them
// when the test ends.
//
// The secret column is written for realism but is never read by the Collector:
// since the signed token_id fact became the row's own id, the lookup is keyed
// on that id alone.
func seedAPIKey(t *testing.T, pool *pgxpool.Pool, secret string) apiKeyFixture {
	t.Helper()

	fixture := apiKeyFixture{
		orgID:     randomUUID(t),
		projectID: randomUUID(t),
		tokenID:   "tok_" + randomHex(t, 6),
	}

	ctx := context.Background()
	_, err := pool.Exec(ctx,
		`INSERT INTO organization (id, slug, name, created_at) VALUES ($1, $2, $3, now())`,
		fixture.orgID, "itest-"+randomHex(t, 6), "collector integration test")
	require.NoError(t, err, "insert organization")

	_, err = pool.Exec(ctx,
		`INSERT INTO project (id, org_id, name, created_at) VALUES ($1, $2, $3, now())`,
		fixture.projectID, fixture.orgID, "itest-"+randomHex(t, 6))
	require.NoError(t, err, "insert project")

	_, err = pool.Exec(ctx,
		`INSERT INTO devtoken (id, project_id, name, prefix, secret, scopes_csv, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, now())`,
		fixture.tokenID, fixture.projectID, "collector-itest", "fty_live", secret, "read_audit")
	require.NoError(t, err, "insert devtoken")

	t.Cleanup(func() {
		// Reverse foreign-key order.
		cleanup := context.Background()
		_, _ = pool.Exec(cleanup, `DELETE FROM devtoken WHERE id = $1`, fixture.tokenID)
		_, _ = pool.Exec(cleanup, `DELETE FROM project WHERE id = $1`, fixture.projectID)
		_, _ = pool.Exec(cleanup, `DELETE FROM organization WHERE id = $1`, fixture.orgID)
	})

	return fixture
}

// revokeAPIKey deletes the key's row, which is what tokens/service.py's
// delete_api_key does — revocation is a missing row, not a flag.
func revokeAPIKey(t *testing.T, pool *pgxpool.Pool, tokenID string) {
	t.Helper()
	tag, err := pool.Exec(context.Background(), `DELETE FROM devtoken WHERE id = $1`, tokenID)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "the key under test should have existed")
}

// ---------------------------------------------------------------------------
// Redpanda
// ---------------------------------------------------------------------------

// createTopic makes a throwaway topic per test so one test's records can never
// be mistaken for another's.
func createTopic(t *testing.T, topic string) {
	t.Helper()

	client, err := kgo.NewClient(kgo.SeedBrokers(broker()))
	require.NoError(t, err)
	admin := kadm.NewClient(client)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	responses, err := admin.CreateTopics(ctx, 3, 1, nil, topic)
	if err != nil {
		client.Close()
		t.Fatalf("cannot reach Redpanda at %s: %v\nStart it with: make redpanda-topics", broker(), err)
	}
	for _, response := range responses {
		require.NoError(t, response.Err, "create topic %s", response.Topic)
	}

	// The client is closed by the cleanup, not deferred here: closing it on the
	// way out of this function would leave the deletion below with a dead
	// client, which is how earlier runs leaked a topic apiece.
	t.Cleanup(func() {
		defer client.Close()

		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancelCleanup()

		// Reported rather than ignored: a failure here is invisible in the
		// broker until topics have piled up for weeks.
		deletions, deleteErr := admin.DeleteTopics(cleanupCtx, topic)
		if deleteErr != nil {
			t.Errorf("could not delete the test topic %s: %v", topic, deleteErr)
			return
		}
		for _, deletion := range deletions {
			if deletion.Err != nil {
				t.Errorf("could not delete the test topic %s: %v", deletion.Topic, deletion.Err)
			}
		}
	})
}

// consumeOne returns the first record on the topic, or fails if none arrives.
func consumeOne(t *testing.T, topic string, timeout time.Duration) *kgo.Record {
	t.Helper()

	client, err := kgo.NewClient(
		kgo.SeedBrokers(broker()),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	require.NoError(t, err)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fetches := client.PollRecords(ctx, 1)
	if err := fetches.Err(); err != nil {
		t.Fatalf("no record on %s within %s: %v", topic, timeout, err)
	}
	records := fetches.Records()
	require.NotEmpty(t, records, "expected at least one record on %s", topic)
	return records[0]
}

// expectNoRecord asserts nothing lands on the topic — used to confirm a
// rejected request never reaches the exporter.
func expectNoRecord(t *testing.T, topic string, within time.Duration) {
	t.Helper()

	client, err := kgo.NewClient(
		kgo.SeedBrokers(broker()),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	require.NoError(t, err)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()

	// This assertion is only meaningful if consuming actually works: an
	// unreachable broker also yields zero records, which would pass a
	// regression where rejected spans DO reach Kafka. Prove reachability
	// first, and treat any non-deadline consume error the same way.
	require.NoError(t, client.Ping(ctx),
		"cannot reach the broker, so seeing no records would prove nothing")

	fetches := client.PollRecords(ctx, 1)
	if err := fetches.Err(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("consuming from %s failed, so seeing no records proves nothing: %v", topic, err)
	}
	if records := fetches.Records(); len(records) > 0 {
		t.Fatalf("expected no records on %s, got %d (first key=%q)",
			topic, len(records), string(records[0].Key))
	}
}

// ---------------------------------------------------------------------------
// The collector process
// ---------------------------------------------------------------------------

type collectorOptions struct {
	publicKeyFile string
	topic         string
	pollInterval  time.Duration
	maxStaleness  time.Duration
}

type runningCollector struct {
	httpEndpoint string
	logPath      string
	// exited carries the process's exit status, so a collector that dies on a
	// bad config fails the test immediately instead of after a readiness
	// timeout.
	exited <-chan error
}

// startCollector runs the real binary against the committed config.yaml,
// overriding only what a test has to isolate.
//
// Driving the committed config rather than a fixture is the point: the
// properties under test live in that file's processor chain and exporter
// settings, so a hand-written test config would verify nothing about what
// actually ships.
func startCollector(t *testing.T, opts collectorOptions) runningCollector {
	t.Helper()

	httpEndpoint := freeAddress(t)
	grpcEndpoint := freeAddress(t)
	logPath := filepath.Join(t.TempDir(), "collector.log")
	logFile, err := os.Create(logPath)
	require.NoError(t, err)

	overridePath := writeOverrideConfig(t, opts, httpEndpoint, grpcEndpoint)

	// Two --config sources rather than --set: the distribution registers only
	// the file and env confmap providers (see builder-config.yaml), and --set
	// needs the yaml provider. Multiple --config flags are merged in order,
	// deeply, so the override below replaces individual leaves and leaves
	// everything else in config.yaml — including the receivers' auth and
	// include_metadata settings — in place.
	args := []string{
		"--config=file:config.yaml",
		"--config=file:" + overridePath,
	}

	cmd := exec.Command(binaryPath(t), args...)
	cmd.Dir = collectorDir(t)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = append(os.Environ(),
		"HEXGATE_COLLECTOR_PUBLIC_KEY_FILE="+opts.publicKeyFile,
		"HEXGATE_COLLECTOR_POSTGRES_DSN="+postgresDSN(),
		"HEXGATE_REDPANDA_BOOTSTRAP_SERVER="+broker(),
	)
	require.NoError(t, cmd.Start(), "start the collector")

	// One owner for Wait(): calling it from both here and the cleanup would
	// race. Closed after the single send so every receive past the first
	// returns immediately — waitUntilReady may have consumed the value on a
	// startup failure, and the cleanup below would otherwise block forever on
	// a channel that will never be sent to again.
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait(); close(exited) }()

	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-exited:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
		_ = logFile.Close()
		if t.Failed() {
			if contents, readErr := os.ReadFile(logPath); readErr == nil {
				t.Logf("collector log:\n%s", contents)
			}
		}
	})

	running := runningCollector{httpEndpoint: httpEndpoint, logPath: logPath, exited: exited}
	waitUntilReady(t, running)
	return running
}

// writeOverrideConfig emits the minimal patch over config.yaml that isolates
// one test: its own ports and topic, and a revocation cache fast enough to
// assert against.
func writeOverrideConfig(t *testing.T, opts collectorOptions, httpEndpoint, grpcEndpoint string) string {
	t.Helper()

	// processors.batch.timeout: config.yaml batches for 5s, which would
	// dominate every assertion here. metadata_keys — the setting actually
	// under test — is deliberately not touched.
	override := fmt.Sprintf(`receivers:
  otlp:
    protocols:
      grpc:
        endpoint: %s
      http:
        endpoint: %s
processors:
  batch:
    timeout: 200ms
exporters:
  kafka:
    traces:
      topic: %s
extensions:
  hexgatebiscuitauth:
    revocation:
      poll_interval: %s
      max_staleness: %s
service:
  telemetry:
    logs:
      # The extension logs rejection reasons at debug, since at ingest volumes
      # they would otherwise flood. The log is only printed when a test fails,
      # so the verbosity costs nothing and is the difference between a
      # diagnosable failure and a bare 401.
      level: debug
`, grpcEndpoint, httpEndpoint, opts.topic, opts.pollInterval, opts.maxStaleness)

	path := filepath.Join(t.TempDir(), "override.yaml")
	require.NoError(t, os.WriteFile(path, []byte(override), 0o600))
	return path
}

// probeClient bounds each individual readiness probe. waitUntilReady's own
// deadline is only re-checked between attempts, so without this a single
// stalled request could hang past it.
var probeClient = &http.Client{Timeout: 2 * time.Second}

// waitUntilReady polls the OTLP endpoint until an unauthenticated request is
// rejected.
//
// A 401 is a stronger readiness signal than a successful TCP connect: it means
// the HTTP server is listening *and* the auth extension is started and
// refusing traffic, which is the state the assertions depend on.
func waitUntilReady(t *testing.T, collector runningCollector) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		// A collector that rejected its config has already exited; there is
		// nothing to wait for.
		select {
		case err := <-collector.exited:
			if contents, readErr := os.ReadFile(collector.logPath); readErr == nil {
				t.Logf("collector log:\n%s", contents)
			}
			t.Fatalf("the collector exited before becoming ready: %v", err)
		default:
		}

		response, err := probeClient.Post(
			"http://"+collector.httpEndpoint+"/v1/traces",
			"application/json",
			strings.NewReader(spanPayload))
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusUnauthorized {
				return
			}
			lastErr = fmt.Errorf("unauthenticated probe returned %d, want 401", response.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}

	if contents, err := os.ReadFile(collector.logPath); err == nil {
		t.Logf("collector log:\n%s", contents)
	}
	t.Fatalf("collector never became ready on %s: %v", collector.httpEndpoint, lastErr)
}

// postClient bounds each span post; http.DefaultClient has no timeout.
var postClient = &http.Client{Timeout: 10 * time.Second}

// postSpans sends one OTLP/HTTP JSON trace request and returns the status code
// and body, failing the test on a transport error. Inside a require.Eventually
// condition use tryPostSpans instead: its FailNow would run on the condition
// goroutine, which is documented as unreliable and kills the retry loop that
// Eventually exists to provide.
func postSpans(t *testing.T, collector runningCollector, credential string) (int, string) {
	t.Helper()

	status, body, err := tryPostSpans(collector, credential)
	require.NoError(t, err)
	return status, body
}

// tryPostSpans is postSpans without test assertions: transport problems come
// back as an error for the caller to treat as a retry or a failure.
func tryPostSpans(collector runningCollector, credential string) (int, string, error) {
	request, err := http.NewRequest(http.MethodPost,
		"http://"+collector.httpEndpoint+"/v1/traces",
		strings.NewReader(spanPayload))
	if err != nil {
		return 0, "", err
	}
	request.Header.Set("Content-Type", "application/json")
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}

	response, err := postClient.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()

	// io.ReadAll, not a single Read: a Read is allowed to return early, and
	// callers assert.Contains against this body.
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, "", err
	}
	return response.StatusCode, string(body), nil
}

// spanPayload is a minimal, valid OTLP/HTTP JSON trace request. Hand-built on
// purpose: the SDK does not emit OTLP yet, and none of these tests need it to.
const spanPayload = `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name",` +
	`"value":{"stringValue":"collector-integration-test"}}]},"scopeSpans":[{"spans":[{` +
	`"traceId":"5b8efff798038103d269b633813fc60c","spanId":"eee19b7ec3c1b174",` +
	`"name":"itest-span","kind":1,"startTimeUnixNano":"1700000000000000000",` +
	`"endTimeUnixNano":"1700000001000000000"}]}]}]}`

// ---------------------------------------------------------------------------
// Key material and tokens
// ---------------------------------------------------------------------------

// writeRootKeypair generates a throwaway signing key and writes its public half
// the way core/keystore.py does: the raw 32 bytes.
//
// Tests mint their own tokens rather than calling the control plane, so they
// need no Python and no running API. The cross-language guarantee — biscuit-go
// verifying what biscuit-python signed — is a separate concern, covered by the
// extension's committed-fixture test
// (TestVerifyBiscuit_when_token_was_minted_by_the_python_platform_then_it_verifies)
// rather than here.
func writeRootKeypair(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "hexgate.pub")
	require.NoError(t, os.WriteFile(path, public, 0o644))
	return private, path
}

// mintEnvelope builds a token shaped like the control plane's and wraps it in
// the fty_ envelope, mirroring core/biscuits.py:mint_token and make_envelope.
func mintEnvelope(t *testing.T, private ed25519.PrivateKey, fixture apiKeyFixture) string {
	t.Helper()

	builder := biscuit.NewBuilder(private)
	facts := []string{
		fmt.Sprintf(`project("%s")`, fixture.projectID),
		fmt.Sprintf(`token_id("%s")`, fixture.tokenID),
		`name("collector-itest")`,
		`env("live")`,
		fmt.Sprintf(`issued_at(%s)`, time.Now().UTC().Format("2006-01-02T15:04:05Z")),
		`scope("read_audit")`,
	}
	for _, source := range facts {
		fact, err := parser.FromStringFact(source)
		require.NoError(t, err, "parse fact %q", source)
		require.NoError(t, builder.AddAuthorityFact(fact))
	}

	token, err := builder.Build()
	require.NoError(t, err)
	serialized, err := token.Serialize()
	require.NoError(t, err)

	// biscuit-python's to_base64() is URL-safe with padding.
	return "fty_live_" + fixture.projectID + "_" + base64.URLEncoding.EncodeToString(serialized)
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

// freeAddress asks the kernel for an unused port so parallel runs and a
// developer's own collector on 4317/4318 cannot collide.
func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return listener.Addr().String()
}

// randomUUID returns a UUID-shaped id, which is what a real project id looks
// like (projects/service.py uses str(uuid.uuid4())).
//
// The shape matters, and not only for realism: the envelope is
// fty_<env>_<project>_<biscuit>, split on its first three underscores, so a
// project id containing an underscore would be truncated and the rest of it
// would be prepended to the base64 payload. Nothing in the platform enforces
// that today — it holds only because project ids are UUIDs.
func randomUUID(t *testing.T) string {
	t.Helper()
	hex := randomHex(t, 16)
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex[0:8], hex[8:12], hex[12:16], hex[16:20], hex[20:32])
}

func randomHex(t *testing.T, bytes int) string {
	t.Helper()
	buffer := make([]byte, bytes)
	_, err := rand.Read(buffer)
	require.NoError(t, err)
	return fmt.Sprintf("%x", buffer)
}
