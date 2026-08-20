package hexgatebiscuitauth

import (
	"errors"
	"fmt"
	"strings"
)

// envelopePrefix matches core/biscuits.py:ENVELOPE_PREFIX.
const envelopePrefix = "fty"

// parseEnvelope splits `fty_<env>_<project>_<biscuit_b64>`.
//
// Mirrors core/biscuits.py:parse_envelope: the Biscuit payload is URL-safe
// base64 and so contains underscores itself, which is why this splits on the
// first three separators only and treats everything after the project segment
// as payload. Go's SplitN(s, "_", 4) is the equivalent of Python's
// str.split("_", 3).
//
// The env and project segments are duplicated outside the Biscuit purely so a
// leaked key is greppable and GitHub secret-scanning can match it. They are
// unsigned, so nothing downstream may trust them — the signed authority facts
// and the key's database row are the sources of truth.
func parseEnvelope(envelope string) (env, projectID, biscuitB64 string, err error) {
	parts := strings.SplitN(envelope, "_", 4)
	if len(parts) != 4 || parts[0] != envelopePrefix {
		return "", "", "", fmt.Errorf(
			"malformed Hexgate token envelope (expected %s_<env>_<project>_<biscuit>)", envelopePrefix)
	}
	if parts[3] == "" {
		return "", "", "", errors.New("Hexgate token envelope carries an empty biscuit payload")
	}
	return parts[1], parts[2], parts[3], nil
}
