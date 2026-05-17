package ssrf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// imdsv2Server simulates an SSRF-vulnerable endpoint that, when given a URL,
// proxies to a fake AWS IMDSv2-style metadata service. IMDSv1 (GET without
// token) returns 401; PUT to /latest/api/token returns a token; subsequent
// GET with the token returns realistic IAM credentials JSON.
//
// Two parameters are honored:
//   - url    : the upstream URL to fetch
//   - method : the HTTP verb used by the SSRF (default GET)
func imdsv2Server(t *testing.T) *httptest.Server {
	t.Helper()

	const token = "AQAEALL0HM5MmF9TOKEN"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		methodParam := strings.ToUpper(r.URL.Query().Get("method"))
		if methodParam == "" {
			methodParam = "GET"
		}

		if !strings.Contains(urlParam, "169.254.169.254") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
			return
		}

		// Simulate the IMDSv2 token endpoint: only PUT yields a token.
		if strings.Contains(urlParam, "/latest/api/token") {
			if methodParam == "PUT" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(token))
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte("Method Not Allowed"))
			return
		}

		// IMDSv2 metadata: require the token header forwarded through SSRF.
		got := r.Header.Get("X-aws-ec2-metadata-token")
		if got != token {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))
			return
		}

		// Realistic IAM credentials JSON from
		// /latest/meta-data/iam/security-credentials/<role>
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{` +
			`"Code":"Success",` +
			`"LastUpdated":"2024-01-01T00:00:00Z",` +
			`"Type":"AWS-HMAC",` +
			`"AccessKeyId":"ASIAIOSFODNN7EXAMPLE",` +
			`"SecretAccessKey":"wJalr",` +
			`"Token":"FQoGZXIvYXdz",` +
			`"Expiration":"2024-01-01T06:00:00Z"` +
			`}`))
	}))

	t.Cleanup(srv.Close)
	return srv
}

func TestDetector_ProbeIMDSv2(t *testing.T) {
	srv := imdsv2Server(t)

	client := internalhttp.NewClient()
	d := New(client)

	finding, err := d.ProbeIMDSv2(context.Background(), srv.URL+"?url=http://example.com", "url", "GET")
	if err != nil {
		t.Fatalf("ProbeIMDSv2 returned error: %v", err)
	}
	if finding == nil {
		t.Fatal("ProbeIMDSv2 returned nil finding for vulnerable IMDSv2 server")
	}

	if finding.Type != "IMDSv2 Token Path Reachable via SSRF" {
		t.Errorf("Type = %q, want %q", finding.Type, "IMDSv2 Token Path Reachable via SSRF")
	}
	if finding.Severity != core.SeverityCritical {
		t.Errorf("Severity = %v, want Critical", finding.Severity)
	}
	if finding.Tool != "ssrf-cloud-advanced-detector" {
		t.Errorf("Tool = %q, want ssrf-cloud-advanced-detector", finding.Tool)
	}
	if len(finding.WSTG) == 0 || finding.WSTG[0] != "WSTG-INPV-19" {
		t.Errorf("WSTG mapping missing/wrong: %v", finding.WSTG)
	}
	if len(finding.Top10) == 0 || finding.Top10[0] != "A01:2025" {
		t.Errorf("Top10 mapping missing/wrong: %v", finding.Top10)
	}
	if len(finding.CWE) == 0 || finding.CWE[0] != "CWE-918" {
		t.Errorf("CWE mapping missing/wrong: %v", finding.CWE)
	}
}

func TestDetector_ProbeIMDSv2_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always echo a benign response regardless of url param.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello world"))
	}))
	t.Cleanup(srv.Close)

	client := internalhttp.NewClient()
	d := New(client)

	finding, err := d.ProbeIMDSv2(context.Background(), srv.URL+"?url=http://example.com", "url", "GET")
	if err != nil {
		t.Fatalf("ProbeIMDSv2 returned error: %v", err)
	}
	if finding != nil {
		t.Errorf("expected nil finding on safe server, got: %+v", finding)
	}
}

// gceMetadataServer simulates an SSRF endpoint that returns a realistic GCE
// computeMetadata response only when Metadata-Flavor: Google is asserted via
// the SSRF (we approximate by requiring the payload to include the GCE path).
func gceMetadataServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")

		if strings.Contains(urlParam, "computeMetadata/v1") ||
			strings.Contains(urlParam, "metadata.google.internal") {
			// Real-looking recursive=true response from GCE IMDS.
			w.Header().Set("Metadata-Flavor", "Google")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`Metadata-Flavor: Google` + "\n" +
				`{"instance":{"serviceAccounts":{"default":{"aliases":["default"],` +
				`"email":"sa@project.iam.gserviceaccount.com",` +
				`"scopes":["https://www.googleapis.com/auth/cloud-platform"]}}},` +
				`"project":{"projectId":"my-proj"}}` + "\n" +
				`/computeMetadata/v1/instance/service-accounts/default/token`))
			return
		}
		if strings.Contains(urlParam, "kubernetes.default.svc.cluster.local") {
			// Simulate kube-apiserver TLS handshake error / 403 JSON
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure",` +
				`"message":"forbidden: User cannot get path /","reason":"Forbidden","code":403}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDetector_ProbeGCEMetadata(t *testing.T) {
	srv := gceMetadataServer(t)

	client := internalhttp.NewClient()
	d := New(client)

	finding, err := d.ProbeGCEMetadata(context.Background(), srv.URL+"?url=http://example.com", "url", "GET")
	if err != nil {
		t.Fatalf("ProbeGCEMetadata returned error: %v", err)
	}
	if finding == nil {
		t.Fatal("ProbeGCEMetadata returned nil finding for vulnerable GCE metadata server")
	}
	if finding.Type != "GCE Cloud Metadata Reachable" {
		t.Errorf("Type = %q, want %q", finding.Type, "GCE Cloud Metadata Reachable")
	}
	if finding.Severity != core.SeverityCritical {
		t.Errorf("Severity = %v, want Critical", finding.Severity)
	}
	if finding.Tool != "ssrf-cloud-advanced-detector" {
		t.Errorf("Tool = %q", finding.Tool)
	}
}

func TestDetector_ProbeGCEMetadata_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("nothing to see here"))
	}))
	t.Cleanup(srv.Close)

	client := internalhttp.NewClient()
	d := New(client)

	finding, err := d.ProbeGCEMetadata(context.Background(), srv.URL+"?url=http://example.com", "url", "GET")
	if err != nil {
		t.Fatalf("ProbeGCEMetadata returned error: %v", err)
	}
	if finding != nil {
		t.Errorf("expected nil finding on safe server, got %+v", finding)
	}
}

// dockerSocketServer simulates an SSRF that surfaces the Docker Engine API
// response (containers/json, version) verbatim.
func dockerSocketServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		if strings.Contains(urlParam, "docker.sock") ||
			strings.Contains(urlParam, "docker:2375") ||
			strings.Contains(urlParam, "/containers/json") ||
			strings.Contains(urlParam, "/v1.41/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Mix of /info and /containers/json indicators.
			_, _ = w.Write([]byte(`{"Containers":12,"ContainersRunning":3,` +
				`"DockerRootDir":"/var/lib/docker",` +
				`"ServerVersion":"24.0.7",` +
				`"Driver":"overlay2"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDetector_ProbeDockerSocket(t *testing.T) {
	srv := dockerSocketServer(t)

	client := internalhttp.NewClient()
	d := New(client)

	finding, err := d.ProbeDockerSocket(context.Background(), srv.URL+"?url=http://example.com", "url", "GET")
	if err != nil {
		t.Fatalf("ProbeDockerSocket returned error: %v", err)
	}
	if finding == nil {
		t.Fatal("ProbeDockerSocket returned nil finding for exposed Docker socket")
	}
	if finding.Type != "Docker Socket Exposed via SSRF" {
		t.Errorf("Type = %q", finding.Type)
	}
	if finding.Severity != core.SeverityCritical {
		t.Errorf("Severity = %v, want Critical", finding.Severity)
	}
	if finding.Tool != "ssrf-cloud-advanced-detector" {
		t.Errorf("Tool = %q", finding.Tool)
	}
}

func TestDetector_ProbeDockerSocket_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"unrelated":"json"}`))
	}))
	t.Cleanup(srv.Close)

	client := internalhttp.NewClient()
	d := New(client)

	finding, err := d.ProbeDockerSocket(context.Background(), srv.URL+"?url=http://example.com", "url", "GET")
	if err != nil {
		t.Fatalf("ProbeDockerSocket returned error: %v", err)
	}
	if finding != nil {
		t.Errorf("expected nil finding on safe server, got %+v", finding)
	}
}

// internalServicesServer simulates SSRF egress to Vault / etcd / Consul.
func internalServicesServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParam := r.URL.Query().Get("url")
		switch {
		case strings.Contains(urlParam, ":8200/v1/sys/health"):
			// Hashicorp Vault /sys/health response
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false,` +
				`"performance_standby":false,"replication_performance_mode":"disabled",` +
				`"version":"1.15.4","cluster_name":"vault-cluster-abc"}`))
			return
		case strings.Contains(urlParam, ":2379"):
			// etcd v2 keys
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"action":"get","node":{"key":"/","dir":true,"nodes":[]}}`))
			return
		case strings.Contains(urlParam, ":8500/v1/agent/self"):
			// consul agent self
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Config":{"Datacenter":"dc1","NodeName":"agent-one",` +
				`"Server":true},"Member":{"Name":"agent-one","Status":1}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDetector_ProbeInternalServices_Vault(t *testing.T) {
	srv := internalServicesServer(t)

	client := internalhttp.NewClient()
	d := New(client)

	findings, err := d.ProbeInternalServices(context.Background(), srv.URL+"?url=http://example.com", "url", "GET")
	if err != nil {
		t.Fatalf("ProbeInternalServices returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("ProbeInternalServices returned no findings for exposed services")
	}

	wantTypes := map[string]bool{
		"Internal Vault Service Reachable":  false,
		"Internal etcd Service Reachable":   false,
		"Internal Consul Service Reachable": false,
	}
	for _, f := range findings {
		if _, ok := wantTypes[f.Type]; ok {
			wantTypes[f.Type] = true
		}
		if f.Severity != core.SeverityCritical {
			t.Errorf("Severity = %v, want Critical (type=%s)", f.Severity, f.Type)
		}
		if f.Tool != "ssrf-cloud-advanced-detector" {
			t.Errorf("Tool = %q (type=%s)", f.Tool, f.Type)
		}
		if len(f.WSTG) == 0 || f.WSTG[0] != "WSTG-INPV-19" {
			t.Errorf("WSTG missing/wrong for type=%s: %v", f.Type, f.WSTG)
		}
	}

	for typ, found := range wantTypes {
		if !found {
			t.Errorf("expected finding type %q, missing", typ)
		}
	}
}

func TestDetector_ProbeInternalServices_NotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("safe response without service banners"))
	}))
	t.Cleanup(srv.Close)

	client := internalhttp.NewClient()
	d := New(client)

	findings, err := d.ProbeInternalServices(context.Background(), srv.URL+"?url=http://example.com", "url", "GET")
	if err != nil {
		t.Fatalf("ProbeInternalServices returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings on safe server, got %d: %+v", len(findings), findings)
	}
}
