package fileupload

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// dangerousExtensions lists file extensions that can lead to code execution.
var dangerousExtensions = []string{".php", ".jsp", ".asp", ".aspx", ".exe", ".sh", ".py"}

// doubleExtensions lists double extension bypass patterns.
var doubleExtensions = []string{".php.jpg", ".php.png", ".jsp.jpg", ".asp.jpg", ".aspx.png"}

// nullByteFilenames lists null byte injection filenames.
var nullByteFilenames = []string{"file.php%00.jpg", "file.jsp%00.png", "file.asp%00.gif"}

// mimeBypassTests maps dangerous extensions to innocent MIME types.
var mimeBypassTests = []struct {
	filename    string
	contentType string
}{
	{"test.php", "image/jpeg"},
	{"test.jsp", "image/png"},
	{"test.asp", "image/gif"},
	{"test.aspx", "image/jpeg"},
}

// uploadSuccessIndicators are strings that suggest a successful upload.
var uploadSuccessIndicators = []string{
	"upload", "success", "uploaded", "file saved", "stored",
	"created", "accepted",
}

// Detector performs File Upload vulnerability detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new File Upload Detector.
func New(client *http.Client) *Detector {
	return &Detector{
		client: client,
	}
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	MaxPayloads       int
	IncludeMIMEBypass bool
	IncludeDoubleExt  bool
	IncludeNullByte   bool
	Timeout           time.Duration
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:       20,
		IncludeMIMEBypass: true,
		IncludeDoubleExt:  true,
		IncludeNullByte:   true,
		Timeout:           10 * time.Second,
	}
}

// DetectionResult contains file upload detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
}

// Name returns the detector name.
func (d *Detector) Name() string {
	return "fileupload-detector"
}

// Detect tests a target URL for file upload vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	if target == "" {
		return result, fmt.Errorf("target URL cannot be empty")
	}

	payloadCount := 0

	// Test dangerous extensions
	for _, ext := range dangerousExtensions {
		if opts.MaxPayloads > 0 && payloadCount >= opts.MaxPayloads {
			break
		}

		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		payloadCount++
		result.TestedPayloads++

		filename := "test" + ext
		body, contentType, err := d.buildMultipartBody(param, filename, "application/octet-stream", "<?php echo 'test'; ?>")
		if err != nil {
			continue
		}

		resp, err := d.client.SendRawBody(ctx, target, method, body, contentType)
		if err != nil {
			continue
		}

		if d.isUploadAccepted(resp, filename) {
			finding := d.createFinding(target, param, filename, "application/octet-stream", resp, "dangerous-extension")
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	// Test MIME type bypass
	if opts.IncludeMIMEBypass {
		for _, test := range mimeBypassTests {
			if opts.MaxPayloads > 0 && payloadCount >= opts.MaxPayloads {
				break
			}

			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			payloadCount++
			result.TestedPayloads++

			body, contentType, err := d.buildMultipartBody(param, test.filename, test.contentType, "<?php echo 'test'; ?>")
			if err != nil {
				continue
			}

			resp, err := d.client.SendRawBody(ctx, target, method, body, contentType)
			if err != nil {
				continue
			}

			if d.isUploadAccepted(resp, test.filename) {
				finding := d.createFinding(target, param, test.filename, test.contentType, resp, "mime-type-bypass")
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				return result, nil
			}
		}
	}

	// Test double extensions
	if opts.IncludeDoubleExt {
		for _, ext := range doubleExtensions {
			if opts.MaxPayloads > 0 && payloadCount >= opts.MaxPayloads {
				break
			}

			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			payloadCount++
			result.TestedPayloads++

			filename := "test" + ext
			body, contentType, err := d.buildMultipartBody(param, filename, "image/jpeg", "<?php echo 'test'; ?>")
			if err != nil {
				continue
			}

			resp, err := d.client.SendRawBody(ctx, target, method, body, contentType)
			if err != nil {
				continue
			}

			if d.isUploadAccepted(resp, filename) {
				finding := d.createFinding(target, param, filename, "image/jpeg", resp, "double-extension-bypass")
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				return result, nil
			}
		}
	}

	// Test null byte filenames
	if opts.IncludeNullByte {
		for _, filename := range nullByteFilenames {
			if opts.MaxPayloads > 0 && payloadCount >= opts.MaxPayloads {
				break
			}

			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			payloadCount++
			result.TestedPayloads++

			body, contentType, err := d.buildMultipartBody(param, filename, "image/jpeg", "<?php echo 'test'; ?>")
			if err != nil {
				continue
			}

			resp, err := d.client.SendRawBody(ctx, target, method, body, contentType)
			if err != nil {
				continue
			}

			if d.isUploadAccepted(resp, filename) {
				finding := d.createFinding(target, param, filename, "image/jpeg", resp, "null-byte-bypass")
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				return result, nil
			}
		}
	}

	return result, nil
}

// buildMultipartBody creates a multipart form body with a file field.
func (d *Detector) buildMultipartBody(fieldName, filename, mimeType, content string) (string, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile(fieldName, filename)
	if err != nil {
		return "", "", fmt.Errorf("failed to create form file: %w", err)
	}

	_, err = part.Write([]byte(content))
	if err != nil {
		return "", "", fmt.Errorf("failed to write file content: %w", err)
	}

	err = writer.Close()
	if err != nil {
		return "", "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	return buf.String(), writer.FormDataContentType(), nil
}

// isUploadAccepted checks if the server accepted the file upload.
func (d *Detector) isUploadAccepted(resp *http.Response, filename string) bool {
	if resp == nil {
		return false
	}

	// Check for success status codes
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return false
	}

	bodyLower := strings.ToLower(resp.Body)

	// Check if response indicates upload success
	for _, indicator := range uploadSuccessIndicators {
		if strings.Contains(bodyLower, indicator) {
			return true
		}
	}

	// Check if uploaded filename appears in response (path disclosure)
	if strings.Contains(resp.Body, filename) {
		return true
	}

	return false
}

// createFinding creates a Finding from a successful file upload test.
func (d *Detector) createFinding(target, param, filename, mimeType string, resp *http.Response, detectionType string) *core.Finding {
	finding := core.NewFinding("File Upload Vulnerability", core.SeverityHigh)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("%s file upload vulnerability detected: server accepted '%s' with content type '%s'",
		detectionType, filename, mimeType)
	finding.Evidence = fmt.Sprintf("Filename: %s\nMIME Type: %s\nDetection: %s\nStatus Code: %d",
		filename, mimeType, detectionType, resp.StatusCode)
	finding.Tool = "fileupload-detector"

	if len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Validate file extensions against an allowlist. " +
		"Check MIME types server-side. " +
		"Rename uploaded files. " +
		"Store uploads outside the web root. " +
		"Scan uploaded files for malicious content."

	finding.WithOWASPMapping(
		[]string{"WSTG-BUSL-08"},
		[]string{"A04:2021"},
		[]string{"CWE-434"},
	)

	return finding
}
