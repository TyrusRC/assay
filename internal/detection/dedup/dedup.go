// Package dedup provides a small generic helper for removing duplicate
// payloads, replacing the per-detector deduplicatePayloads functions that
// were copied verbatim across many detection packages.
package dedup

// ByKey returns items with duplicates removed, preserving the order of first
// occurrence. Two items are considered duplicates when key returns the same
// string for both. The returned slice is always non-nil.
func ByKey[T any](items []T, key func(T) string) []T {
	seen := make(map[string]struct{}, len(items))
	out := make([]T, 0, len(items))
	for _, it := range items {
		k := key(it)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, it)
	}
	return out
}
