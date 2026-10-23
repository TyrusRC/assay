package iast

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// DefaultAddr is the default listen address for the IAST callback server.
const DefaultAddr = ":7880"

// SinkType constants mirror the Acunetix AcuSensor event types.
const (
	SinkSQLQuery       = "sql_query"
	SinkSysCommand     = "sys_command"
	SinkFileOpen       = "file_open"
	SinkCreateFile     = "create_file"
	SinkDeleteFile     = "delete_file"
	SinkURLOpen        = "url_open"
	SinkXPathQuery     = "xpath_query"
	SinkLDAPQuery      = "ldap_query"
	SinkUnserialize    = "unserialize"
	SinkTemplateRender = "template_render"
	SinkSendMail       = "send_mail"
	SinkSetHeader      = "set_header"
	SinkXMLParse       = "xml_parse"
	SinkMongoDBQuery   = "mongodb_query"
)

// SinkHit is a single report from a deployed sensor: a taint marker
// reached a dangerous sink.
type SinkHit struct {
	MarkerID   string    `json:"marker_id"`
	SinkType   string    `json:"sink_type"`
	SinkValue  string    `json:"sink_value"`
	StackTrace string    `json:"stack_trace,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	SourceIP   string    `json:"source_ip,omitempty"`
}

// Server is the IAST callback receiver. It listens for HTTP POST
// requests from sensors deployed in the target application.
type Server struct {
	addr       string
	findings   chan *SinkHit
	mu         sync.RWMutex
	hits       []SinkHit
	httpServer *http.Server
	started    bool
}

// NewServer creates an IAST callback server. addr defaults to ":7880"
// when empty.
func NewServer(addr string) *Server {
	if addr == "" {
		addr = DefaultAddr
	}
	return &Server{
		addr:     addr,
		findings: make(chan *SinkHit, 64),
	}
}

// Start begins listening for sensor callbacks. It blocks until ctx is
// cancelled or Stop is called.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/sink", s.handleSink)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	s.httpServer = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		BaseContext:        func(_ net.Listener) context.Context { return ctx },
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("iast: listen %s: %w", s.addr, err)
	}

	s.mu.Lock()
	s.started = true
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Stop performs a graceful shutdown of the callback server.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.httpServer == nil {
		return nil
	}
	s.started = false
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.httpServer.Shutdown(ctx)
}

// Addr returns the configured listen address.
func (s *Server) Addr() string { return s.addr }

// Hits returns a copy of all received sink hits.
func (s *Server) Hits() []SinkHit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SinkHit, len(s.hits))
	copy(out, s.hits)
	return out
}

// HitsByMarker returns all sink hits for a given marker ID.
func (s *Server) HitsByMarker(markerID string) []SinkHit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []SinkHit
	for _, h := range s.hits {
		if h.MarkerID == markerID {
			out = append(out, h)
		}
	}
	return out
}

// WaitForHit blocks until a SinkHit with the given marker ID arrives
// or timeout expires. Returns nil on timeout.
func (s *Server) WaitForHit(markerID string, timeout time.Duration) *SinkHit {
	deadline := time.After(timeout)
	for {
		select {
		case hit := <-s.findings:
			// Re-enqueue: other goroutines may also be waiting.
			s.mu.Lock()
			s.hits = append(s.hits, *hit)
			s.mu.Unlock()
			if hit.MarkerID == markerID {
				return hit
			}
		case <-deadline:
			return nil
		}
	}
}

// Findings returns the channel that receives every new SinkHit as it
// arrives. Callers that read this channel MUST be running before
// sensors fire, or the channel buffer (64) will fill and block the
// HTTP handler.
func (s *Server) Findings() <-chan *SinkHit { return s.findings }

func (s *Server) handleSink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var hit SinkHit
	if err := json.Unmarshal(body, &hit); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if hit.MarkerID == "" {
		http.Error(w, "marker_id required", http.StatusUnprocessableEntity)
		return
	}

	if hit.Timestamp.IsZero() {
		hit.Timestamp = time.Now()
	}
	hit.SourceIP = r.RemoteAddr

	// Store and notify.
	s.mu.Lock()
	s.hits = append(s.hits, hit)
	s.mu.Unlock()

	select {
	case s.findings <- &hit:
	default:
		// Channel full — drop oldest to prevent blocking.
	}

	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintln(w, `{"status":"accepted"}`)
}
