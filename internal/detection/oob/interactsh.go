package oob

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

// Payload type constants for different vulnerability classes.
const (
	PayloadTypeSQLi = "sqli"
	PayloadTypeXXE  = "xxe"
	PayloadTypeSSRF = "ssrf"
	PayloadTypeLFI  = "lfi"
	PayloadTypeRCE  = "rce"
	PayloadTypeSSTI = "ssti"
)

// Payload represents an OOB payload with tracking information.
type Payload struct {
	ID       string    `json:"id"`
	URL      string    `json:"url"`
	Type     string    `json:"type"`
	Created  time.Time `json:"created"`
	Metadata map[string]string
}

// DNSPayload returns the payload suitable for DNS-based OOB.
func (p *Payload) DNSPayload() string {
	// Remove protocol if present
	url := p.URL
	if strings.HasPrefix(url, "http://") {
		url = url[7:]
	} else if strings.HasPrefix(url, "https://") {
		url = url[8:]
	}
	return url
}

// HTTPPayload returns the payload as an HTTP URL.
func (p *Payload) HTTPPayload() string {
	if strings.HasPrefix(p.URL, "http://") || strings.HasPrefix(p.URL, "https://") {
		return p.URL
	}
	return "http://" + p.URL
}

// Interaction represents an OOB interaction received from the server.
type Interaction struct {
	Protocol    string            `json:"protocol"`
	FullID      string            `json:"full_id"`
	RawRequest  string            `json:"raw_request,omitempty"`
	RawResponse string            `json:"raw_response,omitempty"`
	RemoteAddr  string            `json:"remote_address"`
	Timestamp   time.Time         `json:"timestamp"`
	PayloadType string            `json:"payload_type,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// String returns a string representation of the interaction.
func (i *Interaction) String() string {
	return fmt.Sprintf("[%s] %s from %s at %s (type: %s)",
		i.Protocol, i.FullID, i.RemoteAddr,
		i.Timestamp.Format(time.RFC3339), i.PayloadType)
}

// Client wraps the interactsh client for OOB testing.
type Client struct {
	client       *client.Client
	serverURL    string
	payloads     map[string]*Payload
	interactions []*Interaction
	// mu protects payloads and interactions.
	mu sync.RWMutex
	// pollMu serializes PollWithTimeout so the underlying interactsh
	// client's StartPolling/StopPolling never overlap across goroutines.
	pollMu sync.Mutex
}

// NewClient creates a new OOB client using interactsh.
func NewClient() (*Client, error) {
	return NewClientWithServer("")
}

// NewClientWithServer creates a new OOB client with a custom server URL.
func NewClientWithServer(serverURL string) (*Client, error) {
	opts := client.DefaultOptions
	if serverURL != "" {
		opts.ServerURL = serverURL
	}

	interactClient, err := client.New(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create interactsh client: %w", err)
	}

	c := &Client{
		client:       interactClient,
		serverURL:    serverURL,
		payloads:     make(map[string]*Payload),
		interactions: make([]*Interaction, 0),
	}

	return c, nil
}

// Close closes the client and cleans up resources.
func (c *Client) Close() {
	if c.client != nil {
		c.client.Close()
	}
}

// GeneratePayload generates a new OOB payload for the given type.
func (c *Client) GeneratePayload(payloadType string) *Payload {
	url := c.client.URL()

	payload := &Payload{
		ID:       extractID(url),
		URL:      url,
		Type:     payloadType,
		Created:  time.Now(),
		Metadata: make(map[string]string),
	}

	c.mu.Lock()
	c.payloads[payload.ID] = payload
	c.mu.Unlock()

	return payload
}

// GeneratePayloads generates multiple payloads for different types.
func (c *Client) GeneratePayloads(types []string) []*Payload {
	payloads := make([]*Payload, len(types))
	for i, t := range types {
		payloads[i] = c.GeneratePayload(t)
	}
	return payloads
}

// extractID extracts the unique ID from the interactsh URL.
func extractID(url string) string {
	// Remove protocol
	if strings.HasPrefix(url, "http://") {
		url = url[7:]
	} else if strings.HasPrefix(url, "https://") {
		url = url[8:]
	}

	// Get subdomain part
	parts := strings.Split(url, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return url
}

// Poll polls for interactions for a specified duration and returns them.
func (c *Client) Poll(ctx context.Context) []*Interaction {
	return c.PollWithTimeout(ctx, 5*time.Second)
}

// PollWithTimeout polls for interactions for a specified duration.
// Concurrent callers are serialized via pollMu so the underlying interactsh
// client's StartPolling/StopPolling pair never overlaps — that pair is not
// safe against concurrent use. Interactions received during the window are
// appended directly to the persistent interactions slice under c.mu and are
// never dropped, regardless of burst size.
func (c *Client) PollWithTimeout(ctx context.Context, duration time.Duration) []*Interaction {
	c.pollMu.Lock()
	defer c.pollMu.Unlock()

	// Capture the slice length at the start so we can return only the
	// interactions that arrived during THIS window. Concurrent callers
	// that queue behind pollMu still see their own window-scoped subset.
	c.mu.Lock()
	startIdx := len(c.interactions)
	c.mu.Unlock()

	c.client.StartPolling(time.Second, c.recordInteraction)

	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-ctx.Done():
	}

	c.client.StopPolling()

	// Return a snapshot of interactions that arrived during this window.
	c.mu.RLock()
	received := append([]*Interaction(nil), c.interactions[startIdx:]...)
	c.mu.RUnlock()
	return received
}

// recordInteraction is the StartPolling callback body. Extracted so the
// no-drop invariant can be unit-tested without a real interactsh server:
// all interactions are persisted under c.mu and never discarded.
func (c *Client) recordInteraction(interaction *server.Interaction) {
	inter := &Interaction{
		Protocol:   interaction.Protocol,
		FullID:     interaction.FullId,
		RawRequest: interaction.RawRequest,
		RemoteAddr: interaction.RemoteAddress,
		Timestamp:  interaction.Timestamp,
	}
	id := extractID(interaction.FullId)
	c.mu.Lock()
	if payload, ok := c.payloads[id]; ok {
		inter.PayloadType = payload.Type
		inter.Metadata = payload.Metadata
	}
	c.interactions = append(c.interactions, inter)
	c.mu.Unlock()
}

// GetInteractions returns all collected interactions.
func (c *Client) GetInteractions() []*Interaction {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*Interaction, len(c.interactions))
	copy(result, c.interactions)
	return result
}

// HasInteraction checks if any interaction was received for a payload.
func (c *Client) HasInteraction(payloadID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, inter := range c.interactions {
		if strings.Contains(inter.FullID, payloadID) {
			return true
		}
	}
	return false
}

// GetPayload returns a payload by ID.
func (c *Client) GetPayload(id string) *Payload {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.payloads[id]
}

// GetURL returns the base URL for generating payloads.
func (c *Client) GetURL() string {
	return c.client.URL()
}
