package hexgatebiscuitauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	biscuit "github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
)

// maxAppendedBlocks caps how many attenuation blocks a token may carry.
//
// Authorizer() verifies one Ed25519 signature per block and Authorize() runs
// a (bounded, but ~2ms) Datalog pass per block, so per-request CPU is linear
// in the block count — and attenuation needs no signing key, so the count is
// chosen by whoever holds the token, including holders of revoked or expired
// ones (both are rejected only after this work is done). Real attenuation
// depth is single digits: the platform mints one authority block and a dev's
// backend adds a narrowing block or two.
const maxAppendedBlocks = 8

// identity holds the facts read out of a verified token's authority block.
//
// ProjectID is the project the token *claimed* at mint time. It is signed, so
// it is not forgeable, but it is a snapshot rather than live state — the
// authoritative project comes from the key's database row. Kept here so a
// divergence between the two can be logged.
type identity struct {
	TokenID   string
	ProjectID string
	Env       string
	Name      string
	Scopes    []string
	IssuedAt  time.Time
}

// verifyBiscuit checks a token's signature and its own embedded checks, then
// reads its authority facts. `now` is the instant a TTL caveat is evaluated
// against.
//
// A nil error means the token was signed by the holder of the private key
// matching rootPub and that none of its checks failed. It says nothing about
// revocation — that is the caller's next step.
func verifyBiscuit(rootPub ed25519.PublicKey, biscuitB64 string, now time.Time) (*identity, error) {
	tokenBytes, err := decodeBiscuit(biscuitB64)
	if err != nil {
		return nil, err
	}

	token, err := biscuit.Unmarshal(tokenBytes)
	if err != nil {
		// Structural decode only — no signature has been checked yet.
		return nil, fmt.Errorf("deserialize biscuit: %w", err)
	}

	// BlockCount() covers appended blocks only (the authority block is held
	// separately), which is exactly the attacker-appendable part. Checked
	// before Authorizer() so an oversized chain costs no signature work.
	if count := token.BlockCount(); count > maxAppendedBlocks {
		return nil, fmt.Errorf(
			"token carries %d appended blocks, more than the %d this collector accepts", count, maxAppendedBlocks)
	}

	// Authorizer() is where the Ed25519 signature chain is verified against
	// the root key. Everything after this point is operating on bytes the
	// platform demonstrably signed.
	authorizer, err := token.Authorizer(rootPub)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// A TTL is minted as `check if time($t), $t < <expiry>`, so the check can
	// only pass if the authorizer supplies `time`. Mirrors the Python side's
	// authorize_token(facts="time(...)").
	authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "time",
		IDs:  []biscuit.Term{biscuit.Date(now)},
	}})

	// The token's own checks are the policy here; this Collector adds no
	// authorization rules of its own, so anything that satisfies its checks
	// is allowed through. Scope enforcement, if it ever applies to ingestion,
	// belongs in a later block of policy, not in a bare allow.
	policy, err := parser.FromStringAuthorizer(`allow if true;`)
	if err != nil {
		return nil, fmt.Errorf("build authorizer policy: %w", err)
	}
	authorizer.AddAuthorizer(policy)

	// Authorize() enforces the embedded checks (a TTL caveat rejects here),
	// and it is also what loads the authority block's facts into the world
	// that the queries below read. Querying before this returns nothing.
	if err := authorizer.Authorize(); err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	return readIdentity(authorizer)
}

// readIdentity pulls the facts the pipeline needs out of a verified token.
//
// Every value here comes from the authority block only, never from a block
// appended later. That matters because attenuation needs no secret —
// core/biscuits.py:attenuate_token lets any holder of a token append blocks
// using an ephemeral keypair, so a token's later blocks are attacker-controlled
// even though its signature chain still validates.
//
// biscuit-go gives us that separation: Authorize() loads the authority block's
// facts into the authorizer's own world, but loads each appended block's facts
// into a *clone* of it (authorizer.go:210 in biscuit-go v2.2.0). Query() reads
// the un-cloned world, so appended facts are invisible here. See
// TestReadIdentity_when_attenuated_block_forges_facts_then_authority_wins.
func readIdentity(authorizer biscuit.Authorizer) (*identity, error) {
	tokenIDs, err := queryStrings(authorizer, "token_id")
	if err != nil {
		return nil, err
	}
	// token_id keys the revocation lookup, so an ambiguous or absent one has
	// to be fatal rather than resolved by picking a winner.
	if len(tokenIDs) != 1 {
		return nil, fmt.Errorf(
			"expected exactly one token_id fact in the token's authority block, found %d", len(tokenIDs))
	}

	id := &identity{TokenID: tokenIDs[0]}

	if id.ProjectID, err = queryOptionalString(authorizer, "project"); err != nil {
		return nil, err
	}
	if id.Env, err = queryOptionalString(authorizer, "env"); err != nil {
		return nil, err
	}
	if id.Name, err = queryOptionalString(authorizer, "name"); err != nil {
		return nil, err
	}
	if id.Scopes, err = queryStrings(authorizer, "scope"); err != nil {
		return nil, err
	}
	if id.IssuedAt, err = queryOptionalDate(authorizer, "issued_at"); err != nil {
		return nil, err
	}
	return id, nil
}

// queryStrings returns every string-valued single-argument fact under the given
// predicate name.
func queryStrings(authorizer biscuit.Authorizer, predicate string) ([]string, error) {
	// The head predicate is arbitrary; a hexgate_ prefix keeps it from
	// colliding with any fact a token might carry.
	rule, err := parser.FromStringRule(fmt.Sprintf("hexgate_extracted($v) <- %s($v)", predicate))
	if err != nil {
		return nil, fmt.Errorf("build %s query: %w", predicate, err)
	}
	facts, err := authorizer.Query(rule)
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", predicate, err)
	}

	values := make([]string, 0, len(facts))
	for _, fact := range facts {
		if len(fact.Predicate.IDs) != 1 {
			continue
		}
		if value, ok := fact.Predicate.IDs[0].(biscuit.String); ok {
			values = append(values, string(value))
		}
	}
	return values, nil
}

// queryOptionalString returns the single value for a predicate, or "" if the
// token carries none. More than one is an error: these are single-valued facts
// by construction (core/biscuits.py:mint_token writes each exactly once), so
// several means something unexpected produced the token.
func queryOptionalString(authorizer biscuit.Authorizer, predicate string) (string, error) {
	values, err := queryStrings(authorizer, predicate)
	if err != nil {
		return "", err
	}
	switch len(values) {
	case 0:
		return "", nil
	case 1:
		return values[0], nil
	default:
		return "", fmt.Errorf("expected at most one %s fact, found %d", predicate, len(values))
	}
}

// queryOptionalDate is queryOptionalString for a Datalog date term. Returns the
// zero time when absent; issued_at is informational, so absence is tolerated.
func queryOptionalDate(authorizer biscuit.Authorizer, predicate string) (time.Time, error) {
	rule, err := parser.FromStringRule(fmt.Sprintf("hexgate_extracted($v) <- %s($v)", predicate))
	if err != nil {
		return time.Time{}, fmt.Errorf("build %s query: %w", predicate, err)
	}
	facts, err := authorizer.Query(rule)
	if err != nil {
		return time.Time{}, fmt.Errorf("query %s: %w", predicate, err)
	}
	for _, fact := range facts {
		if len(fact.Predicate.IDs) != 1 {
			continue
		}
		if value, ok := fact.Predicate.IDs[0].(biscuit.Date); ok {
			return time.Time(value), nil
		}
	}
	return time.Time{}, nil
}

// decodeBiscuit base64-decodes the envelope's payload segment.
//
// biscuit-python's Biscuit.to_base64() emits URL-safe base64 *with* padding,
// which is what the platform mints today. The unpadded form is accepted too,
// since trailing '=' is the character most likely to be lost in transit through
// a shell, a form, or a copy-paste.
func decodeBiscuit(payload string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := enc.DecodeString(payload); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("biscuit payload is not valid URL-safe base64")
}
