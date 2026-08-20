package hexgatebiscuitauth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeKeySource stands in for Postgres. Each load() returns the next queued
// result, repeating the last one once the queue is drained.
type fakeKeySource struct {
	mu      sync.Mutex
	results []keyLoadResult
	calls   int
	closed  bool
}

type keyLoadResult struct {
	keys map[string]string
	err  error
}

func (f *fakeKeySource) load(context.Context) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	result := f.results[min(f.calls-1, len(f.results)-1)]
	return result.keys, result.err
}

func (f *fakeKeySource) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}

func (f *fakeKeySource) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func testRevocationConfig() RevocationConfig {
	return RevocationConfig{
		Enabled:      true,
		DSN:          "postgres://localhost/test",
		PollInterval: 20 * time.Second,
		MaxStaleness: 2 * time.Minute,
	}
}

// newLoadedCache returns a cache holding one snapshot taken at `takenAt`, with
// the clock pinned to `now`, bypassing start() so no goroutine is involved.
func newLoadedCache(keys map[string]string, takenAt, now time.Time) *revocationCache {
	cache := newRevocationCache(&fakeKeySource{}, testRevocationConfig(), zap.NewNop())
	cache.now = func() time.Time { return now }
	cache.current = snapshot{projectByTokenID: keys, takenAt: takenAt}
	return cache
}

func TestRevocationCacheLookup_happy_path(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	cache := newLoadedCache(map[string]string{"tok_abc": "support-bot"}, now.Add(-5*time.Second), now)

	projectID, err := cache.lookup("tok_abc")

	require.NoError(t, err)
	assert.Equal(t, "support-bot", projectID)
}

// Revoking deletes the row (tokens/service.py:delete_api_key), so a revoked key
// is simply one that is no longer in the snapshot.
func TestRevocationCacheLookup_when_token_is_absent_then_the_key_is_unknown(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	cache := newLoadedCache(map[string]string{"tok_abc": "support-bot"}, now, now)

	_, err := cache.lookup("tok_revoked")

	require.ErrorIs(t, err, errUnknownAPIKey)
}

// Without this, a database outage would freeze the revocation list and every
// key revoked during it would keep working until the outage ended.
func TestRevocationCacheLookup_when_snapshot_is_older_than_max_staleness_then_all_lookups_fail(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	cache := newLoadedCache(map[string]string{"tok_abc": "support-bot"}, now.Add(-5*time.Minute), now)

	_, err := cache.lookup("tok_abc")

	require.ErrorIs(t, err, errCacheStale)
}

func TestRevocationCacheLookup_when_snapshot_is_exactly_at_max_staleness_then_it_is_still_served(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	cache := newLoadedCache(map[string]string{"tok_abc": "support-bot"}, now.Add(-2*time.Minute), now)

	projectID, err := cache.lookup("tok_abc")

	require.NoError(t, err)
	assert.Equal(t, "support-bot", projectID)
}

func TestRevocationCacheLookup_when_no_snapshot_has_loaded_then_lookups_fail(t *testing.T) {
	cache := newRevocationCache(&fakeKeySource{}, testRevocationConfig(), zap.NewNop())

	_, err := cache.lookup("tok_abc")

	require.ErrorIs(t, err, errCacheNotLoaded)
}

func TestRevocationCacheRefresh_happy_path(t *testing.T) {
	source := &fakeKeySource{results: []keyLoadResult{
		{keys: map[string]string{"tok_abc": "support-bot"}},
	}}
	cache := newRevocationCache(source, testRevocationConfig(), zap.NewNop())

	require.NoError(t, cache.refresh(context.Background()))

	projectID, err := cache.lookup("tok_abc")
	require.NoError(t, err)
	assert.Equal(t, "support-bot", projectID)
}

// A refresh swaps the whole snapshot, so a key deleted upstream disappears
// rather than lingering from the previous read.
func TestRevocationCacheRefresh_when_a_key_is_removed_upstream_then_it_stops_resolving(t *testing.T) {
	source := &fakeKeySource{results: []keyLoadResult{
		{keys: map[string]string{"tok_abc": "support-bot", "tok_def": "other"}},
		{keys: map[string]string{"tok_abc": "support-bot"}},
	}}
	cache := newRevocationCache(source, testRevocationConfig(), zap.NewNop())

	require.NoError(t, cache.refresh(context.Background()))
	_, err := cache.lookup("tok_def")
	require.NoError(t, err)

	require.NoError(t, cache.refresh(context.Background()))
	_, err = cache.lookup("tok_def")

	require.ErrorIs(t, err, errUnknownAPIKey)
}

// Booting with no revocation list would mean accepting revoked keys, so the
// Collector must refuse to start instead.
func TestRevocationCacheStart_when_the_first_load_fails_then_start_returns_an_error(t *testing.T) {
	source := &fakeKeySource{results: []keyLoadResult{{err: errors.New("connection refused")}}}
	cache := newRevocationCache(source, testRevocationConfig(), zap.NewNop())

	err := cache.start(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "initial api-key load")
	assert.Contains(t, err.Error(), "connection refused")
}

func TestRevocationCacheStart_happy_path(t *testing.T) {
	source := &fakeKeySource{results: []keyLoadResult{
		{keys: map[string]string{"tok_abc": "support-bot"}},
	}}
	cache := newRevocationCache(source, testRevocationConfig(), zap.NewNop())

	require.NoError(t, cache.start(context.Background()))
	t.Cleanup(cache.shutdown)

	projectID, err := cache.lookup("tok_abc")
	require.NoError(t, err)
	assert.Equal(t, "support-bot", projectID)
	assert.Equal(t, 1, source.callCount())
}

// The poller must survive a failed refresh rather than exiting, otherwise one
// transient database blip would silently end all future refreshes.
func TestRevocationCachePoll_when_a_refresh_fails_then_polling_continues(t *testing.T) {
	source := &fakeKeySource{results: []keyLoadResult{
		{keys: map[string]string{"tok_abc": "support-bot"}},
		{err: errors.New("connection reset")},
		{keys: map[string]string{"tok_abc": "moved-project"}},
	}}
	cfg := testRevocationConfig()
	cfg.PollInterval = time.Millisecond
	cache := newRevocationCache(source, cfg, zap.NewNop())

	require.NoError(t, cache.start(context.Background()))
	t.Cleanup(cache.shutdown)

	// The failing second load must not stop the third from landing.
	require.Eventually(t, func() bool {
		projectID, err := cache.lookup("tok_abc")
		return err == nil && projectID == "moved-project"
	}, 2*time.Second, 5*time.Millisecond)
}

// A failed refresh keeps the previous snapshot rather than emptying it, so
// traffic is not rejected over a transient blip.
func TestRevocationCacheRefresh_when_a_load_fails_then_the_previous_snapshot_is_kept(t *testing.T) {
	source := &fakeKeySource{results: []keyLoadResult{
		{keys: map[string]string{"tok_abc": "support-bot"}},
		{err: errors.New("connection reset")},
	}}
	cache := newRevocationCache(source, testRevocationConfig(), zap.NewNop())
	require.NoError(t, cache.refresh(context.Background()))

	require.Error(t, cache.refresh(context.Background()))

	projectID, err := cache.lookup("tok_abc")
	require.NoError(t, err)
	assert.Equal(t, "support-bot", projectID)
}

func TestRevocationCacheShutdown_happy_path(t *testing.T) {
	source := &fakeKeySource{results: []keyLoadResult{{keys: map[string]string{}}}}
	cache := newRevocationCache(source, testRevocationConfig(), zap.NewNop())
	require.NoError(t, cache.start(context.Background()))

	cache.shutdown()

	assert.True(t, source.closed, "shutdown must release the database pool")
}
