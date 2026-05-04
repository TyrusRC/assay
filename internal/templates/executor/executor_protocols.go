package executor

import (
	"context"
	"fmt"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
)

// executeDNS executes a DNS query from a template.
func (e *Executor) executeDNS(ctx context.Context, tmpl *templates.Template, query *templates.DNSQuery, targetURL string) ([]*templates.ExecutionResult, error) {
	dnsResult, err := e.dnsExecutor.Execute(ctx, targetURL, query)
	if err != nil {
		return nil, err
	}

	result := &templates.ExecutionResult{
		TemplateID:    tmpl.ID,
		TemplateName:  tmpl.Info.Name,
		Severity:      tmpl.Info.Severity,
		URL:           targetURL,
		Matched:       dnsResult.Matched,
		MatchedAt:     dnsResult.Query,
		ExtractedData: dnsResult.ExtractedData,
		Timestamp:     time.Now(),
		Request:       fmt.Sprintf("DNS %s %s", dnsResult.Type, dnsResult.Query),
		Response:      dnsResult.Raw,
	}

	if dnsResult.Error != nil {
		result.Error = dnsResult.Error
	}

	return []*templates.ExecutionResult{result}, nil
}

// executeNetwork executes a network probe from a template.
func (e *Executor) executeNetwork(ctx context.Context, tmpl *templates.Template, probe *templates.NetworkProbe, targetURL string) ([]*templates.ExecutionResult, error) {
	networkResult, err := e.networkExecutor.Execute(ctx, targetURL, probe)
	if err != nil {
		return nil, err
	}

	result := &templates.ExecutionResult{
		TemplateID:    tmpl.ID,
		TemplateName:  tmpl.Info.Name,
		Severity:      tmpl.Info.Severity,
		URL:           targetURL,
		Matched:       networkResult.Matched,
		MatchedAt:     fmt.Sprintf("%s:%s", networkResult.Host, networkResult.Port),
		ExtractedData: networkResult.ExtractedData,
		Timestamp:     time.Now(),
		Request:       fmt.Sprintf("TCP %s:%s", networkResult.Host, networkResult.Port),
		Response:      networkResult.Banner,
	}

	if networkResult.Error != nil {
		result.Error = networkResult.Error
	}

	return []*templates.ExecutionResult{result}, nil
}

// executeSSL executes an SSL probe from a template and wraps the result into ExecutionResult.
func (e *Executor) executeSSL(ctx context.Context, tmpl *templates.Template, probe *templates.SSLProbe, targetURL string) ([]*templates.ExecutionResult, error) {
	sslResult, err := e.sslExecutor.Execute(ctx, targetURL, probe)
	if err != nil {
		return nil, err
	}

	result := &templates.ExecutionResult{
		TemplateID:    tmpl.ID,
		TemplateName:  tmpl.Info.Name,
		Severity:      tmpl.Info.Severity,
		URL:           targetURL,
		Matched:       sslResult.Matched,
		MatchedAt:     fmt.Sprintf("%s:%s", sslResult.Host, sslResult.Port),
		ExtractedData: sslResult.ExtractedData,
		Timestamp:     time.Now(),
		Request:       fmt.Sprintf("SSL %s:%s", sslResult.Host, sslResult.Port),
		Response:      sslResult.Raw,
	}

	if sslResult.Error != nil {
		result.Error = sslResult.Error
	}

	return []*templates.ExecutionResult{result}, nil
}
