package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/easyenclave/easyenclave/v2/internal/agent/app"
	agentconfig "github.com/easyenclave/easyenclave/v2/internal/agent/config"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := app.DefaultConfig()

	loader := agentconfig.DefaultLoader()
	rawConfig, source, err := loader.Load()
	if err != nil {
		logger.Error("failed to load launcher config", "error", err)
		os.Exit(1)
	}
	runtimeCfg := agentconfig.ToRuntime(rawConfig)
	cfg.NodeSize = runtimeCfg.NodeSize
	cfg.Datacenter = runtimeCfg.Datacenter
	cfg.VMName = runtimeCfg.VMName
	cfg.SchedulerLabels = runtimeCfg.SchedulerLabels

	if adminPort := parseAdminPort(rawConfig); adminPort > 0 {
		cfg.Addr = ":" + strconv.Itoa(adminPort)
	}
	if v := os.Getenv("AGENT_ADDR"); v != "" {
		cfg.Addr = v
	}

	logger.Info(
		"agent runtime config loaded",
		"source", source,
		"mode", runtimeCfg.Mode,
		"vm_name", cfg.VMName,
		"node_size", cfg.NodeSize,
		"datacenter", cfg.Datacenter,
		"addr", cfg.Addr,
	)
	if strings.ToLower(runtimeCfg.Mode) != "agent" {
		logger.Warn("agent binary started with non-agent mode config", "mode", runtimeCfg.Mode)
	}

	a, err := app.New(cfg, logger)
	if err != nil {
		logger.Error("failed to create agent", "error", err)
		os.Exit(1)
	}

	go func() {
		if err := a.Start(); err != nil {
			logger.Error("agent stopped", "error", err)
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = a.Shutdown(ctx)
}

func parseAdminPort(cfg map[string]any) int {
	v, ok := cfg["admin_port"]
	if !ok || v == nil {
		return 0
	}
	switch typed := v.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case string:
		typed = strings.TrimSpace(typed)
		if typed == "" {
			return 0
		}
		port, err := strconv.Atoi(typed)
		if err != nil {
			return 0
		}
		return port
	default:
		return 0
	}
}
