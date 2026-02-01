package matchers

import (
	"strings"

	"github.com/antchfx/htmlquery"
	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
	"github.com/swiss-knife-for-web-security/skws/internal/templates"
	"golang.org/x/net/html"
)

// matchXPath evaluates XPath expressions against XML/HTML responses.
func (e *MatcherEngine) matchXPath(m *templates.Matcher, resp *Response) (bool, []string) {
	content := e.getMatchPart(m.Part, resp)
	if content == "" {
		return false, nil
	}

	condition := strings.ToLower(m.Condition)
	if condition == "" {
		condition = "or"
	}

	var extracts []string
	matchCount := 0

	// Determine if content is XML or HTML based on content type
	isXML := isXMLContent(resp.ContentType, content)

	for _, xpathExpr := range m.XPath {
		matched, extracted := e.evaluateXPath(xpathExpr, content, isXML)
		if matched {
			matchCount++
			if len(extracted) > 0 {
				extracts = append(extracts, extracted...)
			}
			if condition == "or" {
				return true, extracts
			}
		} else if condition == "and" {
			return false, nil
		}
	}

	if condition == "and" {
		return matchCount == len(m.XPath), extracts
	}
	return matchCount > 0, extracts
}

// evaluateXPath evaluates a single XPath expression.
func (e *MatcherEngine) evaluateXPath(expr string, content string, isXML bool) (bool, []string) {
	// Check if this is a count() or other function that returns a boolean/number
	if strings.HasPrefix(expr, "count(") || strings.Contains(expr, " = ") || strings.Contains(expr, " > ") || strings.Contains(expr, " < ") {
		return e.evaluateXPathExpression(expr, content, isXML)
	}

	if isXML {
		return e.evaluateXMLXPath(expr, content)
	}
	return e.evaluateHTMLXPath(expr, content)
}

// evaluateHTMLXPath evaluates XPath against HTML content.
func (e *MatcherEngine) evaluateHTMLXPath(expr string, content string) (bool, []string) {
	doc, err := htmlquery.Parse(strings.NewReader(content))
	if err != nil {
		return false, nil
	}

	// Check if this is an attribute extraction
	if strings.HasSuffix(expr, "/@href") || strings.HasSuffix(expr, "/@src") ||
		strings.HasSuffix(expr, "/@class") || strings.HasSuffix(expr, "/@id") ||
		strings.Contains(expr, "/@") {
		return e.extractHTMLAttribute(expr, doc)
	}

	nodes, err := htmlquery.QueryAll(doc, expr)
	if err != nil {
		return false, nil
	}

	if len(nodes) == 0 {
		return false, nil
	}

	var extracts []string
	for _, node := range nodes {
		text := htmlquery.InnerText(node)
		if text != "" {
			extracts = append(extracts, text)
		}
	}

	return true, extracts
}

// extractHTMLAttribute extracts attribute values from HTML using XPath.
func (e *MatcherEngine) extractHTMLAttribute(expr string, doc *html.Node) (bool, []string) {
	// Split expression to get element path and attribute
	attrIdx := strings.LastIndex(expr, "/@")
	if attrIdx == -1 {
		return false, nil
	}

	elementPath := expr[:attrIdx]
	attrName := expr[attrIdx+2:]

	nodes, err := htmlquery.QueryAll(doc, elementPath)
	if err != nil || len(nodes) == 0 {
		return false, nil
	}

	var extracts []string
	for _, node := range nodes {
		attrValue := htmlquery.SelectAttr(node, attrName)
		if attrValue != "" {
			extracts = append(extracts, attrValue)
		}
	}

	return len(extracts) > 0, extracts
}

// evaluateXMLXPath evaluates XPath against XML content.
func (e *MatcherEngine) evaluateXMLXPath(expr string, content string) (bool, []string) {
	doc, err := xmlquery.Parse(strings.NewReader(content))
	if err != nil {
		return false, nil
	}

	nodes, err := xmlquery.QueryAll(doc, expr)
	if err != nil {
		return false, nil
	}

	if len(nodes) == 0 {
		return false, nil
	}

	var extracts []string
	for _, node := range nodes {
		text := node.InnerText()
		if text != "" {
			extracts = append(extracts, text)
		}
	}

	return true, extracts
}

// evaluateXPathExpression evaluates XPath expressions that return boolean/number results.
func (e *MatcherEngine) evaluateXPathExpression(expr string, content string, isXML bool) (bool, []string) {
	// Compile the XPath expression
	xpathExpr, err := xpath.Compile(expr)
	if err != nil {
		return false, nil
	}

	if isXML {
		doc, err := xmlquery.Parse(strings.NewReader(content))
		if err != nil {
			return false, nil
		}

		result := xpathExpr.Evaluate(xmlquery.CreateXPathNavigator(doc))
		return evaluateXPathResult(result), nil
	}

	doc, err := htmlquery.Parse(strings.NewReader(content))
	if err != nil {
		return false, nil
	}

	result := xpathExpr.Evaluate(htmlquery.CreateXPathNavigator(doc))
	return evaluateXPathResult(result), nil
}

// evaluateXPathResult converts XPath result to boolean.
func evaluateXPathResult(result interface{}) bool {
	switch v := result.(type) {
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		return v != ""
	default:
		return result != nil
	}
}

// isXMLContent determines if content should be parsed as XML based on content type.
func isXMLContent(contentType, content string) bool {
	contentType = strings.ToLower(contentType)

	// Check content type header
	if strings.Contains(contentType, "xml") {
		return true
	}
	if strings.Contains(contentType, "html") {
		return false
	}

	// Check content for XML declaration
	trimmed := strings.TrimSpace(content)
	if strings.HasPrefix(trimmed, "<?xml") {
		return true
	}

	// Default to HTML for lenient parsing
	return false
}
