package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// Digest uniquely identifies the canonical content of a statement.
// Format: "sha256:" followed by 64 lowercase hex characters.
type Digest string

// DigestAlgorithm names the hash algorithm used for all digests.
const DigestAlgorithm = "SHA-256"

// DigestPrefix is the textual prefix carried by every digest.
const DigestPrefix = "sha256:"

// String returns the canonical digest string.
func (d Digest) String() string { return string(d) }

// IsZero reports whether the digest is unset.
func (d Digest) IsZero() bool { return d == "" }

// canonicalJSON produces a deterministic JSON encoding:
//   - object keys are emitted in lexicographic order,
//   - no insignificant whitespace is emitted,
//   - struct fields follow a fixed declaration order.
//
// Inputs are restricted to statements (basic types, time.Time and
// map[string]string), so encoding cannot fail; callers rely on that.
func canonicalJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic("provenance: cannot canonically encode: " + err.Error())
	}
	var node any
	if err := json.Unmarshal(raw, &node); err != nil {
		panic("provenance: cannot reparse canonical encoding: " + err.Error())
	}
	out, err := json.Marshal(canonicalize(node))
	if err != nil {
		panic("provenance: cannot emit canonical encoding: " + err.Error())
	}
	return out
}

// canonicalize recursively reorders object keys in a decoded JSON tree.
func canonicalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make(map[string]any, len(t))
		for _, k := range keys {
			ordered[k] = canonicalize(t[k])
		}
		return ordered
	case []any:
		for i := range t {
			t[i] = canonicalize(t[i])
		}
		return t
	default:
		return v
	}
}

// computeDigest returns the SHA-256 digest of the canonical encoding of v.
func computeDigest(v any) Digest {
	sum := sha256.Sum256(canonicalJSON(v))
	return Digest(DigestPrefix + hex.EncodeToString(sum[:]))
}
