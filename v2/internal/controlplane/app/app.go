package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

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

	mu         sync.Mutex
	challenges map[string]challengeRecord
	agents     map[string]*agentRecord
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
	a := &App{
		cfg:        cfg,
		logger:     logger,
		mux:        mux,
		challenges: map[string]challengeRecord{},
		agents:     map[string]*agentRecord{},
	}
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

type challengeRecord struct {
	VMName    string
	ExpiresAt time.Time
}

type agentRecord struct {
	AgentID        string
	VMName         string
	NodeSize       string
	Datacenter     string
	Secret         string
	RegisteredAt   time.Time
	LastHeartbeat  time.Time
	Health         string
	Status         string
	DeployedApp    string
	DeploymentID   string
	LastTDXReport  string
	LastQuoteError string
}
