package reporting

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/TyrusRC/assay/internal/core"
)

type junitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Errors   int              `xml:"errors,attr"`
	Suites   []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

// WriteJUnit writes the report as JUnit XML. Each finding becomes a failing
// testcase so CI runners surface vulnerabilities as test failures; a clean
// scan emits a single passing placeholder testcase so the suite reads green.
func (r *Report) WriteJUnit(w io.Writer) error {
	findings := r.ScanResult.Findings

	suite := junitTestSuite{Name: toolName}
	for _, f := range findings {
		suite.TestCases = append(suite.TestCases, junitTestCase{
			Name:      fmt.Sprintf("%s at %s", f.Type, f.URL),
			ClassName: ruleID(f.Type),
			Failure: &junitFailure{
				Message: junitFailureMessage(f),
				Type:    string(f.Severity),
				Body:    junitFailureBody(f),
			},
		})
	}
	if len(findings) == 0 {
		suite.TestCases = append(suite.TestCases, junitTestCase{
			Name:      "no vulnerabilities detected",
			ClassName: toolName,
		})
	}
	suite.Tests = len(suite.TestCases)
	suite.Failures = len(findings)

	doc := junitTestSuites{
		Name:     toolName,
		Tests:    suite.Tests,
		Failures: suite.Failures,
		Suites:   []junitTestSuite{suite},
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

func junitFailureMessage(f *core.Finding) string {
	if f.Parameter != "" {
		return fmt.Sprintf("%s [%s] in parameter %q", f.Type, f.Severity, f.Parameter)
	}
	return fmt.Sprintf("%s [%s]", f.Type, f.Severity)
}

func junitFailureBody(f *core.Finding) string {
	body := fmt.Sprintf("URL: %s\nSeverity: %s\nConfidence: %s\n", f.URL, f.Severity, f.Confidence)
	if f.CVSS > 0 {
		body += fmt.Sprintf("CVSS: %.1f %s\n", f.CVSS, f.CVSSVector)
	}
	if f.Description != "" {
		body += "\n" + f.Description + "\n"
	}
	if f.Evidence != "" {
		body += "\nEvidence:\n" + f.Evidence + "\n"
	}
	if f.Remediation != "" {
		body += "\nRemediation: " + f.Remediation + "\n"
	}
	return body
}
