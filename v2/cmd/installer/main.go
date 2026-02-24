package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/easyenclave/easyenclave/v2/internal/installer/host"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg := host.DefaultConfig()
	cfg.AgentSourcePath = resolveAgentSourcePath()
	cfg.ServiceName = envOrDefault("EE_AGENT_SERVICE_NAME", cfg.ServiceName)
	cfg.InstallRoot = envOrDefault("EE_INSTALL_ROOT", cfg.InstallRoot)
	cfg.SystemdDir = envOrDefault("EE_SYSTEMD_DIR", cfg.SystemdDir)
	cfg.EnvDir = envOrDefault("EE_ENV_DIR", cfg.EnvDir)
	cfg.AgentUser = envOrDefault("EE_AGENT_USER", cfg.AgentUser)
	cfg.AgentGroup = envOrDefault("EE_AGENT_GROUP", cfg.AgentGroup)
	cfg.SkipSystemd = strings.EqualFold(strings.TrimSpace(os.Getenv("EE_SKIP_SYSTEMD")), "true")
	cfg.DryRun = strings.EqualFold(strings.TrimSpace(os.Getenv("EE_DRY_RUN")), "true")
	cfg.RunAgentNow = strings.EqualFold(strings.TrimSpace(os.Getenv("EE_RUN_AGENT_NOW")), "true")

	if agentAddr := strings.TrimSpace(os.Getenv("AGENT_ADDR")); agentAddr != "" {
		cfg.EnvVars["AGENT_ADDR"] = agentAddr
	}
	if configPath := strings.TrimSpace(os.Getenv("EASYENCLAVE_CONFIG")); configPath != "" {
		cfg.EnvVars["EASYENCLAVE_CONFIG"] = configPath
	}
	if networkName := strings.TrimSpace(os.Getenv("EASYENCLAVE_NETWORK_NAME")); networkName != "" {
		cfg.EnvVars["EASYENCLAVE_NETWORK_NAME"] = networkName
	}
	if cpURL := strings.TrimSpace(os.Getenv("CONTROL_PLANE_URL")); cpURL != "" {
		cfg.EnvVars["CONTROL_PLANE_URL"] = cpURL
	}

	installer, err := host.New(cfg)
	if err != nil {
		logger.Error("invalid installer config", "error", err)
		os.Exit(1)
	}
	if err := installer.Install(); err != nil {
		logger.Error("installer failed", "error", err)
		os.Exit(1)
	}

	logger.Info(
		"agent installer completed",
		"agent_source", cfg.AgentSourcePath,
		"agent_install_path", cfg.AgentInstallPath(),
		"service_file", cfg.ServiceFilePath(),
		"env_file", cfg.EnvFilePath(),
		"skip_systemd", cfg.SkipSystemd,
		"dry_run", cfg.DryRun,
		"run_agent_now", cfg.RunAgentNow,
	)
}

func resolveAgentSourcePath() string {
	if v := strings.TrimSpace(os.Getenv("EE_AGENT_SOURCE")); v != "" {
		return v
	}
	exe, err := os.Executable()
	if err != nil {
		return "agent"
	}
	return filepath.Join(filepath.Dir(exe), "agent")
}

func envOrDefault(name, fallback string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	return v
}
