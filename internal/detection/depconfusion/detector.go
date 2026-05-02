// Package depconfusion detects internal-package leakage that enables
// dependency-confusion attacks. A target leaks the names of its
// internal packages whenever it serves the manifest itself
// (package.json / composer.json / pom.xml / requirements.txt) on a
// public path. An attacker who learns those names can publish a
// malicious package to the public registry under the same name; if
// any of the target's build tooling resolves that registry without
// scope-pinning, the attacker's payload runs at install time.
//
// The detector probes the host for common manifest paths, then:
//   - Parses npm package.json and flags any dependency name that does
//     NOT begin with `@` (scope) AND does not exist on the public
//     npmjs.org registry. Unscoped names that don't resolve publicly
//     are the canonical dependency-confusion candidates.
//   - For non-JSON manifests we degrade to "manifest exposed" — still
//     a Low/Medium finding because internal package names were
//     leaked. The unresolved-on-public-registry probe is npm-only;
//     PyPI / Packagist are out of scope (different registry shapes).
package depconfusion

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// manifestPaths are the canonical "I leaked my internal package
// names" file paths. Each entry is paired with the language ecosystem
// the manifest belongs to so the report cites it correctly.
var manifestPaths = []struct {
	path, ecosystem string
}{
	{"/package.json", "npm"},
	{"/package-lock.json", "npm"},
	{"/composer.json", "composer"},
	{"/composer.lock", "composer"},
	{"/yarn.lock", "npm"},
	{"/requirements.txt", "pypi"},
	{"/Pipfile", "pypi"},
	{"/pom.xml", "maven"},
	{"/Gemfile.lock", "rubygems"},
}

// publicNPMRegistry is queried to verify whether a leaked package
// name is already taken on the public registry. A 404 means the
// attacker can register it.
const publicNPMRegistry = "https://registry.npmjs.org/"

// Detector probes the host for manifest leaks.
type Detector struct {
	client *skwshttp.Client
}

// New returns a Detector wired to the project's shared HTTP client.
func New(client *skwshttp.Client) *Detector {
	return &Detector{client: client}
}

// Result carries findings emitted by Detect.
type Result struct {
	Findings []*core.Finding
}

// Detect walks each candidate manifest path, fetches it, and emits a
// finding when the response is plausibly the manifest (right
// content-type or recognisable JSON shape). For npm manifests we
// additionally probe the public registry per dependency name and
// upgrade the severity when an unscoped name is unregistered.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	base, err := url.Parse(targetURL)
	if err != nil {
		return res, nil
	}

	for _, entry := range manifestPaths {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		probe := *base
		probe.Path = entry.path
		probe.RawQuery = ""

		resp, err := d.client.Get(ctx, probe.String())
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		if !looksManifest(entry.path, resp.ContentType, resp.Body) {
			continue
		}

		if entry.ecosystem == "npm" && strings.HasSuffix(entry.path, "package.json") {
			vulnerable := d.findUnregisteredNPMDeps(ctx, resp.Body)
			if len(vulnerable) > 0 {
				res.Findings = append(res.Findings,
					buildFinding(probe.String(), entry.path, entry.ecosystem, vulnerable, core.SeverityHigh))
				continue
			}
		}

		// Manifest exposed but no clear confusion candidate (or non-npm).
		res.Findings = append(res.Findings,
			buildFinding(probe.String(), entry.path, entry.ecosystem, nil, core.SeverityLow))
	}
	return res, nil
}

// findUnregisteredNPMDeps parses a package.json body and returns the
// names of dependencies that are unscoped AND absent from the public
// npm registry — the dependency-confusion sweet spot.
func (d *Detector) findUnregisteredNPMDeps(ctx context.Context, body string) []string {
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return nil
	}
	names := map[string]struct{}{}
	for _, key := range []string{"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"} {
		obj, _ := doc[key].(map[string]interface{})
		for name := range obj {
			if name == "" || strings.HasPrefix(name, "@") {
				continue
			}
			names[name] = struct{}{}
		}
	}
	var vulnerable []string
	for name := range names {
		if !d.npmExists(ctx, name) {
			vulnerable = append(vulnerable, name)
		}
		// Cap how many we probe so a 200-dependency manifest doesn't
		// trigger 200 outbound calls.
		if len(vulnerable) >= 5 {
			break
		}
	}
	return vulnerable
}

// npmExists asks the public npmjs.org registry whether a given name
// is registered. 200 = registered (safe); 404 = unregistered (the
// attacker can claim it).
func (d *Detector) npmExists(ctx context.Context, name string) bool {
	resp, err := d.client.Get(ctx, publicNPMRegistry+url.PathEscape(name))
	if err != nil || resp == nil {
		// Network blip — fail closed (assume registered) so we don't FP.
		return true
	}
	return resp.StatusCode != http.StatusNotFound
}

// looksManifest filters out generic SPA fall-through pages. JSON
// manifests must parse as an object; non-JSON manifests just need
// non-empty bodies and a recognisable token.
func looksManifest(path, contentType, body string) bool {
	bodyTrim := strings.TrimSpace(body)
	if bodyTrim == "" {
		return false
	}
	switch {
	case strings.HasSuffix(path, ".json"), strings.HasSuffix(path, ".lock") && strings.HasPrefix(bodyTrim, "{"):
		return strings.HasPrefix(bodyTrim, "{") || strings.HasPrefix(bodyTrim, "[")
	case strings.HasSuffix(path, ".xml"):
		return strings.Contains(bodyTrim, "<project") || strings.Contains(bodyTrim, "<dependencies")
	case strings.HasSuffix(path, ".txt"):
		return strings.Contains(bodyTrim, "==") || strings.Contains(bodyTrim, ">=")
	case strings.HasSuffix(path, ".lock"):
		return strings.Contains(bodyTrim, "specs:") || strings.Contains(bodyTrim, "version") ||
			strings.Contains(bodyTrim, "PLATFORMS")
	case strings.HasSuffix(path, "/Pipfile"):
		return strings.Contains(bodyTrim, "[packages]") || strings.Contains(bodyTrim, "[[source]]")
	}
	_ = contentType
	return true
}

func buildFinding(target, path, ecosystem string, vulnerable []string, severity core.Severity) *core.Finding {
	title := "Internal Package Manifest Exposed"
	if len(vulnerable) > 0 {
		title = "Dependency Confusion Candidate (" + ecosystem + ")"
	}
	finding := core.NewFinding(title, severity)
	finding.URL = target
	finding.Parameter = path
	finding.Tool = "depconfusion"
	finding.Confidence = core.ConfidenceHigh
	if len(vulnerable) > 0 {
		finding.Description = fmt.Sprintf(
			"The %s manifest at %s lists internal dependencies that are NOT registered on the public npm registry: %s. An attacker can publish a malicious package under any of those names; build tooling that resolves the public registry without scope-pinning will install the attacker's code.",
			ecosystem, path, strings.Join(vulnerable, ", "),
		)
		finding.Evidence = "Manifest path: " + path + "\nUnregistered dependencies: " + strings.Join(vulnerable, ", ")
	} else {
		finding.Description = fmt.Sprintf(
			"The %s manifest at %s is reachable from the public internet, leaking internal package names. Even when no specific dependency-confusion candidate exists right now, the leak gives attackers a target list for future registry-takeover attempts.",
			ecosystem, path,
		)
		finding.Evidence = "Manifest path: " + path + "\nEcosystem: " + ecosystem
	}
	finding.Remediation = "Do not deploy raw build manifests with the application. Block /package.json / composer.json / pom.xml / requirements.txt at the edge or build them out of the production artefact. Pin every internal package to a private scope (`@yourorg/...`) and configure your registry resolver with `--registry` lock-files so unscoped names cannot resolve to the public registry."
	finding.WithOWASPMapping(
		[]string{"WSTG-CONF-09"},
		[]string{"A06:2025"},
		[]string{"CWE-1357"},
	)
	finding.APITop10 = []string{"API8:2023", "API9:2023"}
	return finding
}
