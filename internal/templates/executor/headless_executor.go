package executor

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/headless"
	"github.com/TyrusRC/assay/internal/templates"
	"github.com/TyrusRC/assay/internal/templates/matchers"
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

	vars := make(map[string]interface{})
	for _, action := range actions {
		if err := e.runAction(ctx, page, target, action, vars); err != nil {
			if action.Action == "navigate" {
				return nil, fmt.Errorf("headless executor: navigate failed: %w", err)
			}
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
func (e *HeadlessExecutor) runAction(ctx context.Context, page *headless.Page, target string, action templates.HeadlessAction, vars map[string]interface{}) error {
	// Apply per-action timeout when set.
	if action.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(action.Timeout)*time.Second)
		defer cancel()
	}

	selector := action.Args["selector"]
	if selector == "" {
		selector = action.Args["element"]
	}

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
		result, err := page.EvalJS(ctx, expr)
		if err != nil {
			return err
		}
		if action.Name != "" {
			vars[action.Name] = result
		}
		return nil

	case "click":
		if selector == "" {
			return fmt.Errorf("headless: click requires selector")
		}
		return page.ClickElement(ctx, selector)

	case "rightclick":
		if selector == "" {
			return fmt.Errorf("headless: rightclick requires selector")
		}
		return page.RightClickElement(ctx, selector)

	case "text", "type":
		if selector == "" {
			return fmt.Errorf("headless: text requires selector")
		}
		value := action.Args["value"]
		if value == "" {
			value = action.Args["text"]
		}
		return page.InputText(ctx, selector, value)

	case "waitload":
		return page.WaitPageLoad(ctx)

	case "waitnavigation":
		wait, err := page.WaitNavigation(ctx)
		if err != nil {
			return err
		}
		return wait()

	case "waitvisible":
		if selector == "" {
			return fmt.Errorf("headless: waitvisible requires selector")
		}
		return page.WaitVisible(ctx, selector)

	case "waitevent":
		event := action.Args["event"]
		if event == "" {
			return nil
		}
		dur := 5 * time.Second
		if d, err := time.ParseDuration(action.Args["timeout"]); err == nil {
			dur = d
		}
		script := fmt.Sprintf(`new Promise(function(resolve) {
			var t = setTimeout(function() { resolve('timeout'); }, %d);
			document.addEventListener(%q, function() { clearTimeout(t); resolve('fired'); }, {once: true});
		})`, dur.Milliseconds(), event)
		_, err := page.EvalJS(ctx, script)
		return err

	case "extract":
		if selector == "" {
			return nil
		}
		attr := action.Args["attribute"]
		var val string
		var err error
		if attr != "" {
			val, err = page.ExtractAttribute(ctx, selector, attr)
		} else {
			val, err = page.ExtractText(ctx, selector)
		}
		if err != nil {
			return err
		}
		name := action.Name
		if name == "" {
			name = "extracted"
		}
		vars[name] = val
		return nil

	case "screenshot":
		path := action.Args["path"]
		if path == "" {
			path = action.Args["to"]
		}
		data, err := page.Screenshot(ctx, path)
		if err != nil {
			return err
		}
		if action.Name != "" {
			vars[action.Name] = fmt.Sprintf("%d bytes", len(data))
		}
		return nil

	case "select":
		if selector == "" {
			return fmt.Errorf("headless: select requires selector")
		}
		value := action.Args["value"]
		return page.SelectOption(ctx, selector, value)

	case "files", "fileinput":
		if selector == "" {
			return fmt.Errorf("headless: files requires selector")
		}
		pathStr := action.Args["path"]
		if pathStr == "" {
			pathStr = action.Args["value"]
		}
		paths := strings.Split(pathStr, ",")
		for i := range paths {
			paths[i] = strings.TrimSpace(paths[i])
		}
		return page.SetFiles(ctx, selector, paths)

	case "sleep":
		waitFor := action.Args["duration"]
		if waitFor == "" {
			waitFor = action.Args["time"]
		}
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

	case "keyboard":
		keys := action.Args["keys"]
		if keys == "" {
			return nil
		}
		expr := fmt.Sprintf(`document.dispatchEvent(new KeyboardEvent('keydown', {key: %q}))`, keys)
		_, err := page.EvalJS(ctx, expr)
		return err

	case "scroll":
		dx, dy := 0.0, 300.0
		if v := action.Args["x"]; v != "" {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				dx = f
			}
		}
		if v := action.Args["y"]; v != "" {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				dy = f
			}
		}
		return page.Scroll(ctx, dx, dy)

	case "setmethod":
		vars["_method"] = action.Args["method"]
		return nil

	case "addheader":
		name := action.Args["name"]
		value := action.Args["value"]
		if name == "" {
			return nil
		}
		headers := map[string]string{name: value}
		return page.SetExtraHeaders(ctx, headers)

	case "deleteheader":
		name := action.Args["name"]
		if name == "" {
			return nil
		}
		return page.SetExtraHeaders(ctx, map[string]string{name: ""})

	case "setbody":
		vars["_body"] = action.Args["body"]
		return nil

	case "getdom":
		return nil

	case "debug":
		return nil

	default:
		return nil
	}
}
