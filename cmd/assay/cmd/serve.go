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

var servePort int

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
  assay serve --port 9000`,
	Args: cobra.NoArgs,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 8080, "Port to listen on")
}

func runServe(cmd *cobra.Command, _ []string) error {
	mux, err := buildServeMux(scanRunner{})
	if err != nil {
		return err
	}

	addr := fmt.Sprintf(":%d", servePort)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "[*] assay dashboard on http://localhost%s\n", addr)
		if serr := srv.ListenAndServe(); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			errCh <- serr
		}
	}()

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "\n[*] shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case serr := <-errCh:
		return fmt.Errorf("server error: %w", serr)
	}
}

// buildServeMux wires the JSON API under /api/ and the embedded SPA at /.
func buildServeMux(runner api.Runner) (http.Handler, error) {
	ui, err := webui.Handler()
	if err != nil {
		return nil, fmt.Errorf("web ui: %w", err)
	}
	apiServer := api.NewServer(runner)

	mux := http.NewServeMux()
	mux.Handle("/api/", apiServer.Handler())
	mux.Handle("/", ui)
	return mux, nil
}
