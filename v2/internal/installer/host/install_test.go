package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderSystemdUnit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.InstallRoot = "/opt/easyenclave"
	cfg.AgentSourcePath = "/tmp/agent-src"
	cfg.AgentArgs = []string{"--some-flag", "value"}
	unit := RenderSystemdUnit(cfg)

	mustContain(t, unit, "ExecStart=/opt/easyenclave/bin/agent --some-flag value")
	mustContain(t, unit, "EnvironmentFile=-/etc/easyenclave/agent.env")
	mustContain(t, unit, "Restart=always")
}

func TestRenderEnvFile(t *testing.T) {
	env := map[string]string{
		"AGENT_ADDR":         ":18081",
		"EASYENCLAVE_CONFIG": "/etc/easyenclave/config.json",
	}
	out := RenderEnvFile(env)
	mustContain(t, out, "AGENT_ADDR=\":18081\"")
	mustContain(t, out, "EASYENCLAVE_CONFIG=\"/etc/easyenclave/config.json\"")
}

func TestInstallWritesFiles(t *testing.T) {
	temp := t.TempDir()
	src := filepath.Join(temp, "agent-src")
	if err := os.WriteFile(src, []byte("bin"), 0o755); err != nil {
		t.Fatalf("write src: %v", err)
	}

	cfg := DefaultConfig()
	cfg.AgentSourcePath = src
	cfg.InstallRoot = filepath.Join(temp, "opt")
	cfg.SystemdDir = filepath.Join(temp, "systemd")
	cfg.EnvDir = filepath.Join(temp, "etc")
	cfg.SkipSystemd = true

	i, err := New(cfg)
	if err != nil {
		t.Fatalf("new installer: %v", err)
	}
	if err := i.Install(); err != nil {
		t.Fatalf("install: %v", err)
	}

	if _, err := os.Stat(cfg.AgentInstallPath()); err != nil {
		t.Fatalf("missing installed agent: %v", err)
	}
	if _, err := os.Stat(cfg.ServiceFilePath()); err != nil {
		t.Fatalf("missing service file: %v", err)
	}
	if _, err := os.Stat(cfg.EnvFilePath()); err != nil {
		t.Fatalf("missing env file: %v", err)
	}
}

func mustContain(t *testing.T, s, needle string) {
	t.Helper()
	if !strings.Contains(s, needle) {
		t.Fatalf("missing %q in %q", needle, s)
	}
}
