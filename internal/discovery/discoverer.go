package discovery

import (
	"context"
	"sync"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// Discoverer finds injectable parameters from a specific source.
type Discoverer interface {
	// Name returns the discoverer's identifier.
	Name() string
	// Discover extracts parameters from the target URL and its HTTP response.
	Discover(ctx context.Context, targetURL string, resp *http.Response) ([]core.Parameter, error)
}

// DiscoveryResult aggregates results from all discoverers.
type DiscoveryResult struct {
	Parameters []core.Parameter
	Errors     []string
	Sources    map[string]int // discoverer name -> param count
}

// Pipeline orchestrates all discoverers concurrently.
type Pipeline struct {
	client      *http.Client
	discoverers []Discoverer
}

// NewPipeline creates a new discovery pipeline with the given HTTP client.
func NewPipeline(client *http.Client) *Pipeline {
	return &Pipeline{
		client:      client,
		discoverers: make([]Discoverer, 0),
	}
}

// Register adds a discoverer to the pipeline.
func (p *Pipeline) Register(d Discoverer) {
	p.discoverers = append(p.discoverers, d)
}

// Discoverers returns the registered discoverers.
func (p *Pipeline) Discoverers() []Discoverer {
	return p.discoverers
}

// Run executes all discoverers concurrently against the target URL.
// It makes a single GET request and passes the response to all discoverers.
// Results are deduplicated by (Name, Location) key.
func (p *Pipeline) Run(ctx context.Context, targetURL string) (*DiscoveryResult, error) {
	result := &DiscoveryResult{
		Parameters: make([]core.Parameter, 0),
		Sources:    make(map[string]int),
	}

	if len(p.discoverers) == 0 {
		return result, nil
	}

	// Make a single GET request to the target
	resp, err := p.client.Get(ctx, targetURL)
	if err != nil {
		return result, err
	}

	// Fan out all discoverers concurrently
	type discoveryOutput struct {
		name   string
		params []core.Parameter
		err    error
	}

	outputCh := make(chan discoveryOutput, len(p.discoverers))
	var wg sync.WaitGroup

	for _, d := range p.discoverers {
		wg.Add(1)
		go func(disc Discoverer) {
			defer wg.Done()
			params, discErr := disc.Discover(ctx, targetURL, resp)
			outputCh <- discoveryOutput{
				name:   disc.Name(),
				params: params,
				err:    discErr,
			}
		}(d)
	}

	// Close channel when all discoverers finish
	go func() {
		wg.Wait()
		close(outputCh)
	}()

	// Collect and deduplicate results
	seen := make(map[string]bool)
	for out := range outputCh {
		if out.err != nil {
			result.Errors = append(result.Errors, out.name+": "+out.err.Error())
			continue
		}
		count := 0
		for _, param := range out.params {
			key := param.Name + ":" + param.Location
			if !seen[key] {
				seen[key] = true
				result.Parameters = append(result.Parameters, param)
				count++
			}
		}
		result.Sources[out.name] = count
	}

	return result, nil
}
