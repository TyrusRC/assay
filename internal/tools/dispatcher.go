package tools

import (
	"fmt"
	"os"
	"strings"
)

// Dispatcher selects which external tools to run based on the
// internal scanner's discovery results. It replaces the "run all
// tools on all targets" approach with Acunetix-style smart routing:
// WordPress detected → run wpscan; SQL injection candidate → run
// sqlmap/ghauri on that specific parameter; etc.
type Dispatcher struct {
	registry *Registry
	verbose  bool
}

// NewDispatcher creates a dispatcher backed by a tool registry.
func NewDispatcher(registry *Registry, verbose bool) *Dispatcher {
	return &Dispatcher{registry: registry, verbose: verbose}
}

// ToolTask pairs a tool with a request enriched by discovery context.
type ToolTask struct {
	Tool    Tool
	Request *ToolRequest
	Reason  string // why this tool was selected
}

// Dispatch examines the scan context and returns the tool tasks that
// should run. Each task targets the right endpoint/parameter for the
// tool's speciality.
func (d *Dispatcher) Dispatch(baseReq *ToolRequest, ctx *ScanContext) []ToolTask {
	if ctx == nil {
		return d.fallbackAll(baseReq)
	}

	var tasks []ToolTask

	// WordPress detected → wpscan
	if ctx.IsWordPress {
		if t := d.registry.ByName("wpscan"); t != nil && t.IsAvailable() {
			req := d.cloneReq(baseReq)
			tasks = append(tasks, ToolTask{
				Tool:    t,
				Request: req,
				Reason:  "WordPress detected",
			})
		}
	}

	// Web server → nikto
	if ctx.ServerSoftware != "" {
		if t := d.registry.ByName("nikto"); t != nil && t.IsAvailable() {
			req := d.cloneReq(baseReq)
			tasks = append(tasks, ToolTask{
				Tool:    t,
				Request: req,
				Reason:  fmt.Sprintf("web server: %s", ctx.ServerSoftware),
			})
		}
	}

	// Route injection candidates to specialised tools.
	sqliURLs := map[string]bool{}
	xssURLs := map[string]bool{}
	cmdiURLs := map[string]bool{}
	sstiURLs := map[string]bool{}

	for _, cand := range ctx.InjectionCandidates {
		switch cand.VulnClass {
		case "sqli":
			key := cand.URL + "|" + cand.Parameter
			if sqliURLs[key] {
				continue
			}
			sqliURLs[key] = true
			tasks = append(tasks, d.taskForCandidate(baseReq, cand, []string{"sqlmap", "ghauri"})...)
		case "xss":
			key := cand.URL + "|" + cand.Parameter
			if xssURLs[key] {
				continue
			}
			xssURLs[key] = true
			tasks = append(tasks, d.taskForCandidate(baseReq, cand, []string{"dalfox"})...)
		case "cmdi":
			key := cand.URL + "|" + cand.Parameter
			if cmdiURLs[key] {
				continue
			}
			cmdiURLs[key] = true
			tasks = append(tasks, d.taskForCandidate(baseReq, cand, []string{"commix"})...)
		case "ssti":
			key := cand.URL + "|" + cand.Parameter
			if sstiURLs[key] {
				continue
			}
			sstiURLs[key] = true
			tasks = append(tasks, d.taskForCandidate(baseReq, cand, []string{"tplmap"})...)
		}
	}

	// If no injection candidates were found, still run the general
	// scanners (sqlmap on root, dalfox on root) as a fallback.
	if len(ctx.InjectionCandidates) == 0 {
		for _, name := range []string{"sqlmap", "dalfox"} {
			if t := d.registry.ByName(name); t != nil && t.IsAvailable() {
				req := d.cloneReq(baseReq)
				tasks = append(tasks, ToolTask{
					Tool:    t,
					Request: req,
					Reason:  "no injection candidates; fallback full scan",
				})
			}
		}
	}

	// Nuclei always runs (template-based, covers CVEs and misconfig).
	if t := d.registry.ByName("nuclei"); t != nil && t.IsAvailable() {
		req := d.cloneReq(baseReq)
		tasks = append(tasks, ToolTask{
			Tool:    t,
			Request: req,
			Reason:  "nuclei template scan",
		})
	}

	if d.verbose {
		fmt.Fprintf(os.Stderr, "[*] smart dispatch: %d tasks from %d candidates, %d techs\n",
			len(tasks), len(ctx.InjectionCandidates), len(ctx.Technologies))
		for _, task := range tasks {
			fmt.Fprintf(os.Stderr, "    %s → %s\n", task.Tool.Name(), task.Reason)
		}
	}

	return tasks
}

// taskForCandidate creates tasks for a specific injection candidate,
// targeting the exact URL and parameter the native scanner flagged.
func (d *Dispatcher) taskForCandidate(base *ToolRequest, cand InjectionCandidate, toolNames []string) []ToolTask {
	var tasks []ToolTask
	for _, name := range toolNames {
		t := d.registry.ByName(name)
		if t == nil || !t.IsAvailable() {
			continue
		}
		req := d.cloneReq(base)
		req.Target = cand.URL

		// Build tool-specific args to target the exact parameter.
		switch name {
		case "sqlmap":
			req.CustomArgs = append(req.CustomArgs, "-p", cand.Parameter)
			if cand.Method != "" {
				req.Method = cand.Method
			}
		case "ghauri":
			req.CustomArgs = append(req.CustomArgs, "-p", cand.Parameter)
			if cand.Method != "" {
				req.Method = cand.Method
			}
		case "dalfox":
			req.CustomArgs = append(req.CustomArgs, "--param", cand.Parameter)
		case "commix":
			req.CustomArgs = append(req.CustomArgs, "--param="+cand.Parameter)
		case "tplmap":
			// tplmap infers the parameter from the URL query or data
		}

		tasks = append(tasks, ToolTask{
			Tool:    t,
			Request: req,
			Reason:  fmt.Sprintf("%s candidate: %s param=%s", cand.VulnClass, cand.URL, cand.Parameter),
		})
		break // first available tool wins for this candidate
	}
	return tasks
}

// fallbackAll returns one task per available tool when no scan context
// is available (e.g. when the internal scanner was disabled).
func (d *Dispatcher) fallbackAll(base *ToolRequest) []ToolTask {
	var tasks []ToolTask
	for _, t := range d.registry.Available() {
		req := d.cloneReq(base)
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
