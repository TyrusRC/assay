package paraminject_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/TyrusRC/assay/internal/payloads/arginject"
	"github.com/TyrusRC/assay/internal/payloads/esi"
	"github.com/TyrusRC/assay/internal/payloads/fileops"
	"github.com/TyrusRC/assay/internal/payloads/javareflect"
	"github.com/TyrusRC/assay/internal/payloads/paraminject"
	"github.com/TyrusRC/assay/internal/payloads/phpinject"
	"github.com/TyrusRC/assay/internal/payloads/solrinject"
)

// TestSharedBaselineCacheAcrossDetectors confirms that a single
// paraminject.Cache instance is honored by all 6 bank-driven detectors
// that opted into caching, dropping per-target baseline GETs from 6 to 1.
// nodejsinject is intentionally excluded — it needs a fresh baseline
// duration for the time-blind probe.
func TestSharedBaselineCacheAcrossDetectors(t *testing.T) {
	var baselineHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Baseline GETs leave the original param value untouched.
		// Per-payload GETs replace the value with a payload — distinguishable
		// because the original baseline value is "v" (one char).
		// ESI also issues a HEAD fingerprint preflight which we deliberately
		// skip — only count GET baselines.
		if r.Method == http.MethodGet && r.URL.Query().Get("p") == "v" {
			atomic.AddInt32(&baselineHits, 1)
		}
		_, _ = w.Write([]byte("baseline-body"))
	}))
	defer srv.Close()

	cache := paraminject.NewCache()
	ctx := context.Background()
	target := srv.URL + "/?p=v" // 1 param, so detectors will actually fire

	// ESI.
	{
		d := esi.New(srv.Client())
		opts := esi.DefaultOptions()
		opts.BaselineCache = cache
		opts.MaxPayloadsPerParam = 1
		_, _ = d.Detect(ctx, target, opts)
	}
	// Solr.
	{
		d := solrinject.New(srv.Client())
		opts := solrinject.DefaultOptions()
		opts.BaselineCache = cache
		opts.MaxPayloadsPerParam = 1
		opts.ConfirmedSolrOnly = false
		_, _ = d.Detect(ctx, target, opts)
	}
	// PHP.
	{
		d := phpinject.New(srv.Client())
		opts := phpinject.DefaultOptions()
		opts.BaselineCache = cache
		opts.MaxPayloadsPerParam = 1
		opts.ConfirmedPHPOnly = false
		_, _ = d.Detect(ctx, target, opts)
	}
	// Java reflect.
	{
		d := javareflect.New(srv.Client())
		opts := javareflect.DefaultOptions()
		opts.BaselineCache = cache
		opts.MaxPayloadsPerParam = 1
		opts.ConfirmedJavaOnly = false
		_, _ = d.Detect(ctx, target, opts)
	}
	// Arginject.
	{
		d := arginject.New(srv.Client())
		opts := arginject.DefaultOptions()
		opts.BaselineCache = cache
		opts.MaxPayloadsPerParam = 1
		_, _ = d.Detect(ctx, target, opts)
	}
	// Fileops.
	{
		d := fileops.New(srv.Client())
		opts := fileops.DefaultOptions()
		opts.BaselineCache = cache
		opts.MaxPayloadsPerParam = 1
		_, _ = d.Detect(ctx, target, opts)
	}

	// All 6 detectors share one baseline. Without caching we'd see 6.
	got := atomic.LoadInt32(&baselineHits)
	if got != 1 {
		t.Errorf("expected 1 baseline GET across 6 detectors with shared cache, got %d", got)
	}
	if cache.Size() != 1 {
		t.Errorf("expected cache size 1, got %d", cache.Size())
	}
}
