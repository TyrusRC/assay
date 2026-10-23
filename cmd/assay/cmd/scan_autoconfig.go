package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// autoConfig runs BEFORE the scan. It probes the target and auto-enables
// features by setting the package-level flag variables that applyCLIFlags
// reads later. The goal: `assay scan <url>` with zero flags does the
// right thing.
func autoConfig(cmd *cobra.Command, targets []string) {
	if len(targets) == 0 {
		return
	}
	target := targets[0]

	// 1. Default profile = "normal" (not empty = bare defaults)
	if profile == "" && !cmd.Flags().Changed("profile") {
		profile = "normal"
	}

	// 2. Map level/risk from profile when not explicitly set
	if !cmd.Flags().Changed("level") {
		switch profile {
		case "quick":
			level = 1
		case "normal":
			level = 2
		case "thorough":
			level = 3
		}
	}
	if !cmd.Flags().Changed("risk") {
		switch profile {
		case "quick":
			risk = 1
		case "normal":
			risk = 1
		case "thorough":
			risk = 2
		}
	}

	// 3. Auto-detect OpenAPI/Swagger spec
	if apiSpecURL == "" && !cmd.Flags().Changed("api-spec") {
		if found := probeAPISpec(target); found != "" {
			apiSpecURL = found
			fmt.Fprintf(os.Stderr, "[auto] API spec detected: %s\n", apiSpecURL)
		}
	}

	// 4. Auto-detect SPA and enable headless crawl
	if !crawl && !noDiscovery && !cmd.Flags().Changed("crawl") {
		if isSPA(target) {
			crawl = true
			if crawlDepth == 1 {
				crawlDepth = 2
			}
			fmt.Fprintln(os.Stderr, "[auto] SPA detected: headless crawl enabled")
		}
	}

	// 5. Auto-enable verification for normal + thorough
	if !cmd.Flags().Changed("verify") {
		switch profile {
		case "normal", "thorough":
			verifyFindings = true
		}
	}

	// 6. Auto-enable checkpoint for long scans
	if checkpointPath == "" && !cmd.Flags().Changed("checkpoint") {
		if timeout > 5*time.Minute || len(targets) > 3 {
			checkpointPath = filepath.Join(os.TempDir(), "assay-checkpoint.json")
			resumePath = checkpointPath
		}
	}

	// 7. Enable stored-XSS at level >= 2 (normal profile)
	// (applyCLIFlags checks `storedXSSOpt || level >= 3`; we lower the
	// threshold here so normal profile gets stored-XSS too.)
	if level >= 2 {
		storedXSSOpt = true
	}

	// 8. Enable state-aware crawl by default (no browser needed)
	if !cmd.Flags().Changed("crawl-states") && !noDiscovery {
		crawlStates = true
	}
}

// probeAPISpec probes common API spec paths and returns the first valid one.
func probeAPISpec(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	base := fmt.Sprintf("%s://%s", u.Scheme, u.Host)

	paths := []string{
		"/openapi.json",
		"/swagger.json",
		"/api-docs",
		"/swagger/v1/swagger.json",
		"/v1/openapi.json",
		"/v2/api-docs",
		"/v3/api-docs",
		"/api/openapi.json",
		"/api/swagger.json",
		"/docs/openapi.json",
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, p := range paths {
		specURL := base + p
		resp, err := client.Get(specURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		var doc map[string]interface{}
		if json.Unmarshal(body, &doc) != nil {
			continue
		}
		if _, ok := doc["openapi"]; ok {
			return specURL
		}
		if _, ok := doc["swagger"]; ok {
			return specURL
		}
		if _, ok := doc["paths"]; ok {
			return specURL
		}
	}
	return ""
}

// isSPA detects whether a target appears to be a Single Page Application.
func isSPA(target string) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()

	html := strings.ToLower(string(body))

	indicators := []string{
		`<div id="app"`,
		`<div id="root"`,
		`<div id="__next"`,
		`<div id="__nuxt"`,
		`ng-app=`,
		`data-reactroot`,
		`__next_data__`,
		`window.__nuxt`,
		`window.__next_data__`,
	}

	for _, ind := range indicators {
		if strings.Contains(html, ind) {
			return true
		}
	}

	// SPA heuristic: body has very little text content but large JS bundles
	scriptCount := strings.Count(html, "<script")
	textLen := len(strings.TrimSpace(stripHTMLTags(html)))
	if scriptCount >= 3 && textLen < 200 {
		return true
	}

	return false
}

// stripHTMLTags removes HTML tags for SPA text-length heuristic.
func stripHTMLTags(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if !inTag {
			b.WriteRune(r)
		}
	}
	return b.String()
}
