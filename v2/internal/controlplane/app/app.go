package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/easyenclave/easyenclave/v2/internal/gen/controlplaneapi"
)

type Config struct {
	Addr string
}

func DefaultConfig() Config {
	return Config{Addr: ":8080"}
}

type App struct {
	cfg    Config
	logger *slog.Logger
	server *http.Server
	mux    *http.ServeMux
}

var _ controlplaneapi.ServerInterface = (*App)(nil)

func New(cfg Config, logger *slog.Logger) (*App, error) {
	if cfg.Addr == "" {
		return nil, errors.New("missing listen addr")
	}
	if logger == nil {
		logger = slog.Default()
	}

	mux := http.NewServeMux()
	a := &App{cfg: cfg, logger: logger, mux: mux}
	controlplaneapi.HandlerFromMux(a, mux)
	a.server = &http.Server{
		Addr:    cfg.Addr,
		Handler: mux,
	}

	return a, nil
}

func (a *App) Start() error {
	a.logger.Info("control-plane listening", "addr", a.cfg.Addr)
	err := a.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (a *App) Shutdown(ctx context.Context) error {
	return a.server.Shutdown(ctx)
}

func (a *App) Handler() http.Handler {
	return a.mux
}
