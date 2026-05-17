// Package spa crawls Single-Page Applications by driving a real
// headless Chromium via internal/headless.Pool.
//
// Unlike a static link extractor, the SPA crawler waits for the page's
// JavaScript bundle to settle (network-idle) before harvesting URLs,
// so it discovers routes that are:
//
//   - rendered by JS into <a href> elements,
//   - registered via history.pushState / replaceState,
//   - announced through the History API after a hash change.
//
// Results are deduplicated and (when SameOriginOnly is set) filtered to
// the start URL's origin.
package spa
