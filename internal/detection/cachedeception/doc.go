// Package cachedeception detects web cache deception (Omer Gil, 2017),
// the class of bug where a request like GET /profile/foo.css returns the
// authenticated user's /profile body and a downstream cache decides to
// store it under the public-looking ".css" key. A subsequent unauthenticated
// request for the same URL then receives the cached private response.
//
// The two preconditions are:
//
//  1. The application maps a deceptive URL (with a cacheable extension or
//     a path-normalization trick) to the same handler as the canonical
//     private URL — equivalent ingress, but a different cache key.
//  2. The shared cache stores responses by URL/extension regardless of
//     whether the response itself is marked private (Cloudflare, Fastly,
//     Akamai, and most CDN defaults all do this for known static
//     extensions like .css, .js, .png, .ico, .svg).
//
// This detector reports the *first* precondition with high confidence by
// pairing an authenticated probe at the deceptive URL against a baseline
// fetch of the canonical URL: same private body returned at a deceptive
// URL is a smoking gun. The optional unauth-replay step proves the *second*
// precondition by showing the response was actually served from cache.
//
// This is intentionally a separate package from cachepoisoning — the two
// attacks share a name only. Cache poisoning weaponizes unkeyed *headers*;
// cache deception weaponizes unkeyed *paths*.
package cachedeception
