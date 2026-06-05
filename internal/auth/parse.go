package auth

import (
	"errors"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// parseLoginForm finds the login form in body and returns its action, method,
// pre-filled (hidden) fields, and the detected username/password field names.
// The form containing an input[type=password] is preferred; otherwise the
// first form is used. action is resolved against base.
func parseLoginForm(body string, base *url.URL) (*loginForm, error) {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	forms := collectForms(doc)
	if len(forms) == 0 {
		return nil, errors.New("auth: no form found")
	}

	chosen := forms[0]
	for _, fn := range forms {
		if formHasPassword(fn) {
			chosen = fn
			break
		}
	}
	return buildLoginForm(chosen, base), nil
}

// collectForms returns every <form> node in document order.
func collectForms(n *html.Node) []*html.Node {
	var forms []*html.Node
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "form" {
			forms = append(forms, node)
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return forms
}

// formHasPassword reports whether the form subtree contains a password input.
func formHasPassword(form *html.Node) bool {
	found := false
	forEachInput(form, func(_, typ, _ string) {
		if strings.EqualFold(typ, "password") {
			found = true
		}
	})
	return found
}

// buildLoginForm extracts action/method/fields from a form node.
func buildLoginForm(form *html.Node, base *url.URL) *loginForm {
	lf := &loginForm{Fields: map[string]string{}}
	for _, attr := range form.Attr {
		switch strings.ToLower(attr.Key) {
		case "action":
			lf.Action = resolveURL(base, attr.Val)
		case "method":
			lf.Method = strings.ToUpper(attr.Val)
		}
	}
	if lf.Action == "" && base != nil {
		lf.Action = base.String()
	}

	forEachInput(form, func(name, typ, value string) {
		if name == "" {
			return
		}
		switch {
		case strings.EqualFold(typ, "password"):
			lf.PassField = name
		case strings.EqualFold(typ, "hidden"):
			lf.Fields[name] = value
		case lf.UserField == "" && isUsernameInput(typ):
			lf.UserField = name
		}
	})
	return lf
}

// isUsernameInput reports whether an input type is a plausible username field.
func isUsernameInput(typ string) bool {
	switch strings.ToLower(typ) {
	case "", "text", "email", "tel":
		return true
	default:
		return false
	}
}

// forEachInput invokes fn(name, type, value) for every <input> in the form
// subtree.
func forEachInput(form *html.Node, fn func(name, typ, value string)) {
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "input" {
			var name, typ, value string
			for _, a := range node.Attr {
				switch strings.ToLower(a.Key) {
				case "name":
					name = a.Val
				case "type":
					typ = a.Val
				case "value":
					value = a.Val
				}
			}
			fn(name, typ, value)
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(form)
}

// resolveURL resolves ref against base, returning ref unchanged when it
// cannot be parsed.
func resolveURL(base *url.URL, ref string) string {
	if ref == "" {
		if base != nil {
			return base.String()
		}
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	if base == nil {
		return u.String()
	}
	return base.ResolveReference(u).String()
}
