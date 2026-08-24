package hexgatebiscuitauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// apiKeyQuery reads the whole live key set.
//
// The table is `devtoken`, not `apikey`: the model was renamed to ApiKey but
// kept __tablename__ = "devtoken" to avoid a migration (models.py:228). No
// join is needed — project_id is denormalised straight onto the row — and no
// tenancy filter either, since the Collector serves every project.
//
// The secret column is deliberately not selected. The signed token_id fact
// *is* the row's primary key (platform-api PR #126), so a verified token can
// be looked up by that id and the Collector never has to hold full
// credentials in memory.
//
// A full-table read is viable because the row count is small: one row per API
// key, thousands across the whole platform rather than millions.
const apiKeyQuery = `SELECT id, project_id FROM devtoken`

// loadTimeout bounds a single read of the key table. Without it, a connection
// that black-holes packets (network partition, an LB holding the socket open)
// would block refresh() forever — and refresh runs inline in the poller's only
// goroutine, so ticks would be dropped while it hangs and polling would never
// recover, even after the database did. Past max_staleness that means every
// request is rejected until a restart. The same bound covers the synchronous
// first load, which would otherwise hang startup.
const loadTimeout = 10 * time.Second

var (
	// errUnknownAPIKey means a validly-signed token's id matches no row,
	// which is what revoking a key leaves behind.
	errUnknownAPIKey = errors.New("api key is revoked or unknown")

	// errCacheStale means we can no longer vouch for the revocation list.
	errCacheStale = errors.New("revocation snapshot is too old to trust")

	errCacheNotLoaded = errors.New("revocation snapshot has not loaded yet")
)

// keySource reads the live API key set as token_id -> project_id.
//
// Narrow on purpose: it keeps every pgx detail in postgresKeySource, so the
// snapshot, staleness and polling logic below can be tested without a database
// or a stub of pgx.Rows.
type keySource interface {
	load(ctx context.Context) (map[string]string, error)
	close()
}

type postgresKeySource struct {
	pool *pgxpool.Pool
}

func (s *postgresKeySource) load(ctx context.Context) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, apiKeyQuery)
	if err != nil {
		return nil, fmt.Errorf("query api keys: %w", err)
	}
	defer rows.Close()

	keys := make(map[string]string)
	for rows.Next() {
		var tokenID, projectID string
		if err := rows.Scan(&tokenID, &projectID); err != nil {
			return nil, fmt.Errorf("scan api key row: %w", err)
		}
		keys[tokenID] = projectID
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read api key rows: %w", err)
	}
	return keys, nil
}

func (s *postgresKeySource) close() { s.pool.Close() }

// snapshot is one complete read of the key table. Replaced wholesale on each
// refresh rather than mutated, so readers always see a self-consistent view.
type snapshot struct {
	projectByTokenID map[string]string
	takenAt          time.Time
}

// revocationCache serves token_id -> project_id from an in-process snapshot,
// refreshed on a timer. Lookups never touch the database.
type revocationCache struct {
	source keySource
	logger *zap.Logger
	cfg    RevocationConfig
	now    func() time.Time
	// loadTimeout is the constant above; a field so tests can shrink it.
	loadTimeout time.Duration

	mu      sync.RWMutex
	current snapshot

	cancel  context.CancelFunc
	stopped chan struct{}
}

func newRevocationCache(source keySource, cfg RevocationConfig, logger *zap.Logger) *revocationCache {
	return &revocationCache{source: source, cfg: cfg, logger: logger, now: time.Now, loadTimeout: loadTimeout}
}

// lookup resolves a verified token_id to the project that currently owns it.
//
// This is the authoritative project_id for the request. The token carries a
// signed project fact too, but that is a mint-time snapshot; the row is live
// state. Preferring the row is the same rule AuditEnvelope already follows by
// resolving project_id server-side instead of trusting the request body.
func (c *revocationCache) lookup(tokenID string) (string, error) {
	c.mu.RLock()
	current := c.current
	c.mu.RUnlock()

	if current.projectByTokenID == nil {
		return "", errCacheNotLoaded
	}
	// Fail closed on staleness. A database outage otherwise freezes the
	// revocation list, and every key revoked during the outage would keep
	// working for as long as it lasted.
	if age := c.now().Sub(current.takenAt); age > c.cfg.MaxStaleness {
		return "", fmt.Errorf("%w: last refreshed %s ago, max_staleness is %s",
			errCacheStale, age.Truncate(time.Second), c.cfg.MaxStaleness)
	}
	projectID, ok := current.projectByTokenID[tokenID]
	if !ok {
		return "", errUnknownAPIKey
	}
	return projectID, nil
}

// start does the first load synchronously, then polls in the background.
//
// The first load is fatal on failure so the Collector refuses to boot rather
// than come up unable to authenticate anything.
func (c *revocationCache) start(ctx context.Context) error {
	if err := c.refresh(ctx); err != nil {
		return fmt.Errorf("initial api-key load: %w", err)
	}

	// Deliberately not derived from ctx: Start()'s context is scoped to
	// startup and may be cancelled once the component is running, which would
	// kill the poller immediately.
	pollCtx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.stopped = make(chan struct{})
	go c.poll(pollCtx)
	return nil
}

func (c *revocationCache) poll(ctx context.Context) {
	defer close(c.stopped)

	ticker := time.NewTicker(c.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.refresh(ctx); err != nil {
				// Keep serving the previous snapshot; MaxStaleness is the
				// backstop that stops this degrading silently forever.
				c.logger.Error("failed to refresh the API key revocation list; "+
					"serving the previous snapshot until max_staleness expires",
					zap.Error(err))
			}
		}
	}
}

func (c *revocationCache) refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.loadTimeout)
	defer cancel()

	keys, err := c.source.load(ctx)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.current = snapshot{projectByTokenID: keys, takenAt: c.now()}
	c.mu.Unlock()

	c.logger.Debug("refreshed the API key revocation list", zap.Int("keys", len(keys)))
	return nil
}

func (c *revocationCache) shutdown() {
	if c.cancel != nil {
		c.cancel()
		<-c.stopped
	}
	if c.source != nil {
		c.source.close()
	}
}
