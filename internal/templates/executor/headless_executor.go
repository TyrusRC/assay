package executor

import (
	"context"
	"fmt"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/headless"
	"github.com/swiss-knife-for-web-security/skws/internal/templates"
	"github.com/swiss-knife-for-web-security/skws/internal/templates/matchers"
)

// HeadlessExecutor executes headless browser-based template steps.
type HeadlessExecutor struct {
	pool          *headless.Pool
	matcherEngine *matchers.MatcherEngine
}

// NewHeadlessExecutor creates a new headless browser executor.
// pool may be nil; Execute will return an error in that case.
func NewHeadlessExecutor(pool *headless.Pool) *HeadlessExecutor {
	return &HeadlessExecutor{
		pool:          pool,
		matcherEngine: matchers.New(),
	}
}

// Execute runs a headless browser step against a target URL.
// It acquires a page from the pool, runs all declared actions,
// retrieves the final DOM, and evaluates matchers against it.
func (e *HeadlessExecutor) Execute(ctx context.Context, target string, step *templates.HeadlessStep) (*templates.ExecutionResult, error) {
	if e.pool == nil {
		return nil, fmt.Errorf("headless executor: browser pool is nil")
	}

	page, err := e.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("headless executor: acquire page: %w", err)
	}
	defer e.pool.Release(page)

	// Collect all actions (support both fields).
	actions := step.Actions
	if len(actions) == 0 {
		actions = step.Steps
	}

	for _, action := range actions {
		if err := e.runAction(ctx, page, target, action); err != nil {
			// Non-fatal: log and continue to next action.
			_ = err
		}
	}

	dom, err := page.GetDOM(ctx)
	if err != nil {
		dom = ""
	}

	resp := &matchers.Response{
		Body: dom,
		Raw:  dom,
		URL:  target,
	}

	matched, extracts := e.matcherEngine.MatchAll(step.Matchers, "", resp, nil)

	return &templates.ExecutionResult{
		Matched:       matched,
		URL:           target,
		ExtractedData: extracts,
		Response:      dom,
		Timestamp:     time.Now(),
	}, nil
}

// runAction performs a single headless browser action on the page.
func (e *HeadlessExecutor) runAction(ctx context.Context, page *headless.Page, target string, action templates.HeadlessAction) error {
	switch action.Action {
	case "navigate":
		url := action.Args["url"]
		if url == "" {
			url = target
		}
		return page.Navigate(ctx, url)

	case "script", "js":
		expr := action.Args["script"]
		if expr == "" {
			expr = action.Args["js"]
		}
		if expr == "" {
			return nil
		}
		_, err := page.EvalJS(ctx, expr)
		return err

	case "getdom":
		// Retrieves DOM; result is collected separately after all actions.
		return nil

	case "wait":
		waitFor := action.Args["duration"]
		if waitFor == "" {
			waitFor = "1s"
		}
		d, err := time.ParseDuration(waitFor)
		if err != nil {
			d = time.Second
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
		return nil

	default:
		// Unknown action: silently ignore.
		return nil
	}
}
