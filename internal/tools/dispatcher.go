package tools

import (
	"fmt"
	"os"
	"strings"
)

// Dispatcher selects which external tools to run based on the internal
// scanner's discovery results. Two modes run together:
//
//   - Autonomous: core tools (sqlmap, dalfox, nikto, nuclei) always run
//     at full strength with their own crawl/param-mining — never gated
//     behind native findings.
//   - Focus (additive): when the native scanner flags a concrete
//     injection candidate, the dispatcher ALSO launches a focused task
//     pinned to that exact parameter. Focus never replaces autonomous.
type Dispatcher struct {
	registry *Registry
	verbose  bool
	thorough bool // thorough profile enables extra tools (commix, ghauri, tplmap)
}

// NewDispatcher creates a dispatcher backed by a tool registry.
func NewDispatcher(registry *Registry, verbose, thorough bool) *Dispatcher {
	return &Dispatcher{registry: registry, verbose: verbose, thorough: thorough}
}

// ToolTask pairs a tool with a request enriched by discovery context.
type ToolTask struct {
	Tool    Tool
	Request *ToolRequest
	Reason  string // why this tool was selected
}

// Dispatch returns autonomous + focused tasks for a target.
func (d *Dispatcher) Dispatch(baseReq *ToolRequest, ctx *ScanContext) []ToolTask {
	if ctx == nil {
		return d.fallbackAll(baseReq)
	}

	var tasks []ToolTask

	// ── Autonomous tasks: always run at full strength ──

	// Nuclei — template-based CVE + misconfig + DAST fuzzing
	tasks = append(tasks, d.autonomous(baseReq, "nuclei", "template scan (CVEs, misconfig, fuzzing)")...)

	// Nikto — web server scanner, always useful
	tasks = append(tasks, d.autonomous(baseReq, "nikto", "web server audit")...)

	// SQLMap — autonomous crawl + forms + smart detection
	tasks = append(tasks, d.autonomous(baseReq, "sqlmap", "autonomous SQLi crawl+forms")...)

	// Dalfox — autonomous XSS with param mining
	tasks = append(tasks, d.autonomous(baseReq, "dalfox", "autonomous XSS with param mining")...)

	// WPScan — only when WordPress detected
	if ctx.IsWordPress {
		tasks = append(tasks, d.autonomous(baseReq, "wpscan", "WordPress detected")...)
	}

	// Thorough profile adds extra tools unconditionally
	if d.thorough {
		tasks = append(tasks, d.autonomous(baseReq, "ghauri", "thorough: fast SQLi")...)
		tasks = append(tasks, d.autonomous(baseReq, "commix", "thorough: command injection")...)
		tasks = append(tasks, d.autonomous(baseReq, "tplmap", "thorough: SSTI detection")...)
	}

	// ── Focus tasks: additive, pinned to native-flagged candidates ──
	seen := map[string]bool{}
	for _, cand := range ctx.InjectionCandidates {
		key := cand.VulnClass + "|" + cand.URL + "|" + cand.Parameter
		if seen[key] {
			continue
		}
		seen[key] = true

		var toolNames []string
		switch cand.VulnClass {
		case "sqli":
			toolNames = []string{"sqlmap", "ghauri"}
		case "xss":
			toolNames = []string{"dalfox"}
		case "cmdi":
			toolNames = []string{"commix"}
		case "ssti":
			toolNames = []string{"tplmap"}
		default:
			continue
		}
		tasks = append(tasks, d.focused(baseReq, cand, toolNames)...)
	}

	if d.verbose {
		fmt.Fprintf(os.Stderr, "[*] smart dispatch: %d tasks (%d autonomous, %d focused from %d candidates)\n",
			len(tasks), len(tasks)-len(seen), len(seen), len(ctx.InjectionCandidates))
		for _, task := range tasks {
			fmt.Fprintf(os.Stderr, "    %s → %s\n", task.Tool.Name(), task.Reason)
		}
	}

	return tasks
}

// autonomous creates one full-strength task for the named tool.
func (d *Dispatcher) autonomous(base *ToolRequest, toolName, reason string) []ToolTask {
	t := d.registry.ByName(toolName)
	if t == nil || !t.IsAvailable() {
		return nil
	}
	req := d.cloneReq(base)
	// Mark as autonomous so tool integrations enable crawl/mining flags.
	req.CustomArgs = append(req.CustomArgs, "--assay-autonomous")
	return []ToolTask{{Tool: t, Request: req, Reason: reason}}
}

// focused creates a task pinned to a specific injection candidate.
func (d *Dispatcher) focused(base *ToolRequest, cand InjectionCandidate, toolNames []string) []ToolTask {
	var tasks []ToolTask
	for _, name := range toolNames {
		t := d.registry.ByName(name)
		if t == nil || !t.IsAvailable() {
			continue
		}
		req := d.cloneReq(base)
		req.Target = cand.URL
		if cand.Method != "" {
			req.Method = cand.Method
		}

		switch name {
		case "sqlmap":
			req.CustomArgs = append(req.CustomArgs, "-p", cand.Parameter)
			if cand.DBMS != "" {
				req.CustomArgs = append(req.CustomArgs, "--dbms="+cand.DBMS)
			}
		case "ghauri":
			req.CustomArgs = append(req.CustomArgs, "-p", cand.Parameter)
			if cand.DBMS != "" {
				req.CustomArgs = append(req.CustomArgs, "--dbms="+cand.DBMS)
			}
		case "dalfox":
			req.CustomArgs = append(req.CustomArgs, "-p", cand.Parameter, "--skip-discovery")
		case "commix":
			req.CustomArgs = append(req.CustomArgs, "--param="+cand.Parameter)
		}

		tasks = append(tasks, ToolTask{
			Tool:    t,
			Request: req,
			Reason:  fmt.Sprintf("FOCUS %s: %s param=%s", cand.VulnClass, cand.URL, cand.Parameter),
		})
		break // first available tool per candidate
	}
	return tasks
}

// fallbackAll returns one task per available tool when no scan context
// is available (e.g. when the internal scanner was disabled).
func (d *Dispatcher) fallbackAll(base *ToolRequest) []ToolTask {
	var tasks []ToolTask
	for _, t := range d.registry.Available() {
		req := d.cloneReq(base)
		req.CustomArgs = append(req.CustomArgs, "--assay-autonomous")
		tasks = append(tasks, ToolTask{
			Tool:    t,
			Request: req,
			Reason:  "no scan context; running all available tools",
		})
	}
	return tasks
}

func (d *Dispatcher) cloneReq(r *ToolRequest) *ToolRequest {
	clone := *r
	clone.Headers = make(map[string]string, len(r.Headers))
	for k, v := range r.Headers {
		clone.Headers[k] = v
	}
	clone.CustomArgs = make([]string, len(r.CustomArgs))
	copy(clone.CustomArgs, r.CustomArgs)
	return &clone
}

// TechMatchesAny returns true if any of the detected technologies
// contain the substring (case-insensitive).
func TechMatchesAny(techs []string, substr string) bool {
	lower := strings.ToLower(substr)
	for _, t := range techs {
		if strings.Contains(strings.ToLower(t), lower) {
			return true
		}
	}
	return false
}

// IsAutonomous checks whether the request carries the autonomous marker.
func IsAutonomous(req *ToolRequest) bool {
	for _, a := range req.CustomArgs {
		if a == "--assay-autonomous" {
			return true
		}
	}
	return false
}

// StripInternalFlags removes assay-internal flags before passing args
// to the external binary.
func StripInternalFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--assay-autonomous" {
			continue
		}
		out = append(out, a)
	}
	return out
}
