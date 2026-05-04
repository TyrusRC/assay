package executor

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
)

// executeWithFlow executes a template using the flow field for multi-protocol orchestration.
func (e *Executor) executeWithFlow(ctx context.Context, tmpl *templates.Template, targetURL string) ([]*templates.ExecutionResult, error) {
	flowEngine := NewFlowEngine()
	steps := flowEngine.Parse(tmpl.Flow)

	var allResults []*templates.ExecutionResult
	previousMatched := false

	for _, step := range steps {
		if step.Operator != "" && !flowEngine.ShouldContinue(step.Operator, previousMatched) {
			break
		}

		var stepResults []*templates.ExecutionResult
		var err error

		switch step.Protocol {
		case "http":
			stepResults, err = e.executeFlowHTTP(ctx, tmpl, targetURL, step.Index)
		case "dns":
			stepResults, err = e.executeFlowDNS(ctx, tmpl, targetURL, step.Index)
		case "ssl":
			stepResults, err = e.executeFlowSSL(ctx, tmpl, targetURL, step.Index)
		case "headless":
			stepResults, err = e.executeFlowHeadless(ctx, tmpl, targetURL, step.Index)
		case "websocket":
			stepResults, err = e.executeFlowWebSocket(ctx, tmpl, targetURL, step.Index)
		case "whois":
			stepResults, err = e.executeFlowWHOIS(ctx, tmpl, targetURL, step.Index)
		default:
			// Unrecognised protocols return empty results
		}

		if err != nil && e.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] flow step %s(%d) error: %v\n", step.Protocol, step.Index, err)
		}

		allResults = append(allResults, stepResults...)
		previousMatched = hasMatch(stepResults)
	}

	return allResults, nil
}

// executeFlowHTTP executes HTTP blocks for a flow step.
// When index is 0, all blocks are executed; otherwise only the 1-based index block is executed.
func (e *Executor) executeFlowHTTP(ctx context.Context, tmpl *templates.Template, targetURL string, index int) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult

	for i := range tmpl.HTTP {
		if index > 0 && i+1 != index {
			continue
		}
		httpResults, err := e.executeHTTP(ctx, tmpl, &tmpl.HTTP[i], targetURL)
		if err != nil {
			return results, err
		}
		results = append(results, httpResults...)
	}

	return results, nil
}

// executeFlowDNS executes DNS blocks for a flow step.
// When index is 0, all blocks are executed; otherwise only the 1-based index block is executed.
func (e *Executor) executeFlowDNS(ctx context.Context, tmpl *templates.Template, targetURL string, index int) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult

	for i := range tmpl.DNS {
		if index > 0 && i+1 != index {
			continue
		}
		dnsResults, err := e.executeDNS(ctx, tmpl, &tmpl.DNS[i], targetURL)
		if err != nil {
			return results, err
		}
		results = append(results, dnsResults...)
	}

	return results, nil
}

// executeFlowSSL executes SSL blocks for a flow step.
// When index is 0, all blocks are executed; otherwise only the 1-based index block is executed.
func (e *Executor) executeFlowSSL(ctx context.Context, tmpl *templates.Template, targetURL string, index int) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult

	for i := range tmpl.SSL {
		if index > 0 && i+1 != index {
			continue
		}
		sslResults, err := e.executeSSL(ctx, tmpl, &tmpl.SSL[i], targetURL)
		if err != nil {
			return results, err
		}
		results = append(results, sslResults...)
	}

	return results, nil
}

// executeFlowHeadless executes Headless blocks for a flow step.
// When index is 0, all blocks are executed; otherwise only the 1-based index block is executed.
func (e *Executor) executeFlowHeadless(ctx context.Context, tmpl *templates.Template, targetURL string, index int) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult

	for i := range tmpl.Headless {
		if index > 0 && i+1 != index {
			continue
		}
		headlessResult, err := e.headlessExecutor.Execute(ctx, targetURL, &tmpl.Headless[i])
		if err != nil {
			return results, err
		}
		if headlessResult != nil {
			stampResult(headlessResult, tmpl, targetURL)
			results = append(results, headlessResult)
		}
	}

	return results, nil
}

// executeFlowWebSocket executes WebSocket blocks for a flow step.
// When index is 0, all blocks are executed; otherwise only the 1-based index block is executed.
func (e *Executor) executeFlowWebSocket(ctx context.Context, tmpl *templates.Template, targetURL string, index int) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult

	for i := range tmpl.Websocket {
		if index > 0 && i+1 != index {
			continue
		}
		wsResult, err := e.websocketExecutor.Execute(ctx, targetURL, &tmpl.Websocket[i])
		if err != nil {
			return results, err
		}
		if wsResult != nil {
			stampResult(wsResult, tmpl, targetURL)
			results = append(results, wsResult)
		}
	}

	return results, nil
}

// executeFlowWHOIS executes WHOIS blocks for a flow step.
// When index is 0, all blocks are executed; otherwise only the 1-based index block is executed.
func (e *Executor) executeFlowWHOIS(ctx context.Context, tmpl *templates.Template, targetURL string, index int) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult

	for i := range tmpl.Whois {
		if index > 0 && i+1 != index {
			continue
		}
		whoisResult, err := e.whoisExecutor.Execute(ctx, targetURL, &tmpl.Whois[i])
		if err != nil {
			return results, err
		}
		if whoisResult != nil {
			stampResult(whoisResult, tmpl, targetURL)
			results = append(results, whoisResult)
		}
	}

	return results, nil
}
