package executor

import (
	"context"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/oob"
)

const interactshPlaceholder = "interact.sh"

// InteractshHelper manages interactsh integration for template execution.
type InteractshHelper struct {
	client  *oob.Client
	payload *oob.Payload
}

// NewInteractshHelper creates a new InteractshHelper.
// When client is nil (no OOB available), placeholder values are used.
func NewInteractshHelper(client *oob.Client) *InteractshHelper {
	h := &InteractshHelper{client: client}
	if client != nil {
		h.payload = client.GeneratePayload(oob.PayloadTypeSSRF)
	}
	return h
}

// GetURL returns the HTTP callback URL, or a placeholder if no client is available.
func (h *InteractshHelper) GetURL() string {
	if h.client == nil || h.payload == nil {
		return interactshPlaceholder
	}
	return h.payload.HTTPPayload()
}

// GetDNSURL returns the DNS callback URL, or a placeholder if no client is available.
func (h *InteractshHelper) GetDNSURL() string {
	if h.client == nil || h.payload == nil {
		return interactshPlaceholder
	}
	return h.payload.DNSPayload()
}

// InjectVariables sets interactsh-related template variables.
func (h *InteractshHelper) InjectVariables(vars map[string]interface{}) {
	httpURL := h.GetURL()
	dnsURL := h.GetDNSURL()

	vars["interactsh-url"] = httpURL
	vars["interactsh_url"] = httpURL
	vars["interactsh-dns-url"] = dnsURL
}

// Poll checks for interactions and returns true if any were received.
func (h *InteractshHelper) Poll(ctx context.Context) bool {
	if h.client == nil || h.payload == nil {
		return false
	}
	interactions := h.client.Poll(ctx)
	return len(interactions) > 0
}

// HasInteraction returns true if an interaction has been received for the current payload.
func (h *InteractshHelper) HasInteraction() bool {
	if h.client == nil || h.payload == nil {
		return false
	}
	return h.client.HasInteraction(h.payload.ID)
}
