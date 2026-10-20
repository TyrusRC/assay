package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/TyrusRC/assay/internal/api"
	"github.com/TyrusRC/assay/internal/scanner"
	"github.com/TyrusRC/assay/internal/webui"
)

var (
	servePort      int
	serveListen    string
	serveStateFile string
	serveAPIKey    string
)

// scanRunner is the production api.Runner: it drives the real scanner.
type scanRunner struct{}

func (scanRunner) Run(ctx context.Context, req api.ScanRequest) (*scanner.ScanResult, error) {
	s := scanner.New()
	defer s.Close()

	internalConfig := scanner.DefaultInternalConfig()
	if req.Profile != "" {
		internalConfig = scanner.GetProfile(req.Profile).Config
	}
	if err := s.SetInternalConfig(internalConfig); err != nil {
		return nil, fmt.Errorf("configure scanner: %w", err)
	}
	if err := s.AddTarget(req.Target); err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}
	registerTools(s)
	return s.Scan(ctx)
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the assay web dashboard and JSON API",
	Long: `Start an HTTP server exposing the assay dashboard (a single-page app)
and its JSON API for launching scans and browsing results.

Examples:
  assay serve
  assay serve --port 9000
  assay serve --listen 0.0.0.0 --api-key my-secret`,
	Args: cobra.NoArgs,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 8080, "Port to listen on")
	serveCmd.Flags().StringVar(&serveListen, "listen", "127.0.0.1", "Address to bind to (use 0.0.0.0 to expose on all interfaces)")
	serveCmd.Flags().StringVar(&serveStateFile, "state-file", "", "Persist scan jobs to this JSON file so they survive a restart (default: in-memory only)")
	serveCmd.Flags().StringVar(&serveAPIKey, "api-key", "", "Bearer token required for API access (also read from ASSAY_API_KEY)")
}

func runServe(cmd *cobra.Command, _ []string) error {
	apiKey := serveAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("ASSAY_API_KEY")
	}

	mux, apiServer, err := buildServeMux(scanRunner{}, api.ServerConfig{APIKey: apiKey})
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", serveListen, servePort)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "[*] assay dashboard on http://%s\n", addr)
		if apiKey != "" {
			fmt.Fprintln(os.Stderr, "[*] API authentication enabled (Bearer token required)")
		} else {
			fmt.Fprintln(os.Stderr, "[!] No --api-key set; API endpoints are unauthenticated (set ASSAY_API_KEY or pass --api-key)")
		}
		if serr := srv.ListenAndServe(); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			errCh <- serr
		}
	}()

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "\n[*] shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := srv.Shutdown(shutdownCtx)
		apiServer.WaitIdle()
		return err
	case serr := <-errCh:
		return fmt.Errorf("server error: %w", serr)
	}
}

// buildServeMux wires the JSON API under /api/ and the embedded SPA at /.
func buildServeMux(runner api.Runner, cfg api.ServerConfig) (http.Handler, *api.Server, error) {
	ui, err := webui.Handler()
	if err != nil {
		return nil, nil, fmt.Errorf("web ui: %w", err)
	}
	var apiServer *api.Server
	if serveStateFile != "" {
		store, serr := api.NewPersistentStore(serveStateFile)
		if serr != nil {
			return nil, nil, fmt.Errorf("job store: %w", serr)
		}
		apiServer = api.NewServerWithStore(runner, store, cfg)
	} else {
		apiServer = api.NewServerWithStore(runner, api.NewStore(), cfg)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", apiServer.Handler())
	mux.Handle("/", ui)
	return mux, apiServer, nil
}
