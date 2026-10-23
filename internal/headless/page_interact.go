// page_interact.go — DOM element interaction methods on Page: click, type,
// wait, select, extract, screenshot, keyboard, scroll, and extra headers.
package headless

import (
	"context"
	"fmt"
	"os"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
	"github.com/ysmood/gson"
)

// ClickElement clicks the first element matching the CSS selector.
func (p *Page) ClickElement(ctx context.Context, selector string) error {
	if p == nil || p.page == nil {
		return fmt.Errorf("headless: page not initialised")
	}
	el, err := p.page.Context(ctx).Element(selector)
	if err != nil {
		return fmt.Errorf("headless: element %q: %w", selector, err)
	}
	return el.Click(proto.InputMouseButtonLeft, 1)
}

// RightClickElement right-clicks the first element matching the CSS selector.
func (p *Page) RightClickElement(ctx context.Context, selector string) error {
	if p == nil || p.page == nil {
		return fmt.Errorf("headless: page not initialised")
	}
	el, err := p.page.Context(ctx).Element(selector)
	if err != nil {
		return fmt.Errorf("headless: element %q: %w", selector, err)
	}
	return el.Click(proto.InputMouseButtonRight, 1)
}

// InputText clears the element matching selector and types text into it.
func (p *Page) InputText(ctx context.Context, selector, text string) error {
	if p == nil || p.page == nil {
		return fmt.Errorf("headless: page not initialised")
	}
	el, err := p.page.Context(ctx).Element(selector)
	if err != nil {
		return fmt.Errorf("headless: element %q: %w", selector, err)
	}
	if err := el.SelectAllText(); err != nil {
		return err
	}
	return el.Input(text)
}

// WaitVisible waits until the element matching selector is visible.
func (p *Page) WaitVisible(ctx context.Context, selector string) error {
	if p == nil || p.page == nil {
		return fmt.Errorf("headless: page not initialised")
	}
	el, err := p.page.Context(ctx).Element(selector)
	if err != nil {
		return fmt.Errorf("headless: element %q: %w", selector, err)
	}
	return el.WaitVisible()
}

// WaitPageLoad waits for the page load event.
func (p *Page) WaitPageLoad(ctx context.Context) error {
	if p == nil || p.page == nil {
		return fmt.Errorf("headless: page not initialised")
	}
	return p.page.Context(ctx).WaitLoad()
}

// WaitNavigation waits for page navigation to complete. Call this BEFORE
// the action that triggers navigation; it returns a wait function.
func (p *Page) WaitNavigation(ctx context.Context) (func() error, error) {
	if p == nil || p.page == nil {
		return nil, fmt.Errorf("headless: page not initialised")
	}
	wait := p.page.Context(ctx).MustWaitNavigation()
	return func() error { wait(); return nil }, nil
}

// SelectOption selects an <option> by value in a <select> matching selector.
func (p *Page) SelectOption(ctx context.Context, selector string, values ...string) error {
	if p == nil || p.page == nil {
		return fmt.Errorf("headless: page not initialised")
	}
	el, err := p.page.Context(ctx).Element(selector)
	if err != nil {
		return fmt.Errorf("headless: element %q: %w", selector, err)
	}
	return el.Select(values, true, rod.SelectorTypeText)
}

// ExtractText returns the text content of the first element matching selector.
func (p *Page) ExtractText(ctx context.Context, selector string) (string, error) {
	if p == nil || p.page == nil {
		return "", fmt.Errorf("headless: page not initialised")
	}
	el, err := p.page.Context(ctx).Element(selector)
	if err != nil {
		return "", fmt.Errorf("headless: element %q: %w", selector, err)
	}
	return el.Text()
}

// ExtractAttribute returns the value of an attribute on the first matching element.
func (p *Page) ExtractAttribute(ctx context.Context, selector, attr string) (string, error) {
	if p == nil || p.page == nil {
		return "", fmt.Errorf("headless: page not initialised")
	}
	el, err := p.page.Context(ctx).Element(selector)
	if err != nil {
		return "", fmt.Errorf("headless: element %q: %w", selector, err)
	}
	val, err := el.Attribute(attr)
	if err != nil {
		return "", err
	}
	if val == nil {
		return "", nil
	}
	return *val, nil
}

// Screenshot captures a PNG screenshot. An empty path returns the bytes
// without writing a file.
func (p *Page) Screenshot(ctx context.Context, path string) ([]byte, error) {
	if p == nil || p.page == nil {
		return nil, fmt.Errorf("headless: page not initialised")
	}
	data, err := p.page.Context(ctx).Screenshot(true, nil)
	if err != nil {
		return nil, err
	}
	if path != "" {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return data, err
		}
	}
	return data, nil
}

// SetFiles sets files on a file input element matching selector.
func (p *Page) SetFiles(ctx context.Context, selector string, paths []string) error {
	if p == nil || p.page == nil {
		return fmt.Errorf("headless: page not initialised")
	}
	el, err := p.page.Context(ctx).Element(selector)
	if err != nil {
		return fmt.Errorf("headless: element %q: %w", selector, err)
	}
	return el.SetFiles(paths)
}

// KeyboardType types keys into the page.
func (p *Page) KeyboardType(ctx context.Context, keys ...input.Key) error {
	if p == nil || p.page == nil {
		return fmt.Errorf("headless: page not initialised")
	}
	return p.page.Context(ctx).Keyboard.Type(keys...)
}

// KeyboardPress presses and releases a key.
func (p *Page) KeyboardPress(ctx context.Context, key input.Key) error {
	if p == nil || p.page == nil {
		return fmt.Errorf("headless: page not initialised")
	}
	return p.page.Context(ctx).Keyboard.Press(key)
}

// Scroll scrolls the page by dx, dy pixels.
func (p *Page) Scroll(ctx context.Context, dx, dy float64) error {
	if p == nil || p.page == nil {
		return fmt.Errorf("headless: page not initialised")
	}
	return p.page.Context(ctx).Mouse.Scroll(dx, dy, 1)
}

// SetExtraHeaders adds custom request headers to all subsequent requests.
func (p *Page) SetExtraHeaders(ctx context.Context, headers map[string]string) error {
	if p == nil || p.page == nil {
		return fmt.Errorf("headless: page not initialised")
	}
	h := make(proto.NetworkHeaders, len(headers))
	for k, v := range headers {
		h[k] = gson.New(v)
	}
	return proto.NetworkSetExtraHTTPHeaders{Headers: h}.Call(p.page)
}
