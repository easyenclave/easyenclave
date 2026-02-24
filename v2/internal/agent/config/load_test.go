package config

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFileFirst(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"mode":"agent","node_size":"tiny"}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	l := Loader{
		ConfigPaths:      []string{configPath},
		ConfigDriveMount: filepath.Join(dir, "mnt"),
		CmdlinePath:      filepath.Join(dir, "cmdline"),
	}
	cfg, src, err := l.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if src != SourceFile {
		t.Fatalf("source=%s want=%s", src, SourceFile)
	}
	if cfg["node_size"] != "tiny" {
		t.Fatalf("node_size=%v", cfg["node_size"])
	}
}

func TestLoadFromConfigDrive(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mnt := filepath.Join(dir, "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mnt, "config.json"), []byte(`{"mode":"control-plane","port":8080}`), 0o644); err != nil {
		t.Fatalf("write config drive file: %v", err)
	}
	l := Loader{
		ConfigPaths:      []string{filepath.Join(dir, "missing.json")},
		ConfigDriveMount: mnt,
		CmdlinePath:      filepath.Join(dir, "cmdline"),
	}
	cfg, src, err := l.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if src != SourceConfigISO {
		t.Fatalf("source=%s want=%s", src, SourceConfigISO)
	}
	if cfg["mode"] != "control-plane" {
		t.Fatalf("mode=%v", cfg["mode"])
	}
}

func TestLoadFromCmdlineConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cmdlinePath := filepath.Join(dir, "cmdline")
	payload := base64.StdEncoding.EncodeToString([]byte(`{"mode":"agent","vm_id":"x1"}`))
	if err := os.WriteFile(cmdlinePath, []byte("ro quiet easyenclave.config="+payload), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	l := Loader{
		ConfigPaths:      []string{filepath.Join(dir, "missing.json")},
		ConfigDriveMount: filepath.Join(dir, "missing-mnt"),
		CmdlinePath:      cmdlinePath,
	}
	cfg, src, err := l.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if src != SourceCmdline {
		t.Fatalf("source=%s want=%s", src, SourceCmdline)
	}
	if cfg["vm_id"] != "x1" {
		t.Fatalf("vm_id=%v", cfg["vm_id"])
	}
}

func TestLoadFromCmdlineConfigZ(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cmdlinePath := filepath.Join(dir, "cmdline")

	rawJSON := map[string]any{"mode": "agent", "node_size": "standard"}
	data, err := json.Marshal(rawJSON)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var b bytes.Buffer
	zw := zlib.NewWriter(&b)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("compress write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("compress close: %v", err)
	}

	payload := base64.StdEncoding.EncodeToString(b.Bytes())
	if err := os.WriteFile(cmdlinePath, []byte("boot=1 easyenclave.configz="+payload), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}

	l := Loader{
		ConfigPaths:      []string{filepath.Join(dir, "missing.json")},
		ConfigDriveMount: filepath.Join(dir, "missing-mnt"),
		CmdlinePath:      cmdlinePath,
	}
	cfg, src, err := l.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if src != SourceCmdline {
		t.Fatalf("source=%s want=%s", src, SourceCmdline)
	}
	if cfg["node_size"] != "standard" {
		t.Fatalf("node_size=%v", cfg["node_size"])
	}
}

func TestLoadDefaultWhenNoSources(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	l := Loader{
		ConfigPaths:      []string{filepath.Join(dir, "missing.json")},
		ConfigDriveMount: filepath.Join(dir, "missing-mnt"),
		CmdlinePath:      filepath.Join(dir, "missing-cmdline"),
	}
	cfg, src, err := l.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if src != SourceDefault {
		t.Fatalf("source=%s want=%s", src, SourceDefault)
	}
	if cfg["mode"] != "agent" {
		t.Fatalf("mode=%v", cfg["mode"])
	}
}
