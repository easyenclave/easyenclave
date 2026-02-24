package config

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	defaultConfigPath  = "/etc/easyenclave/config.json"
	defaultCmdlinePath = "/proc/cmdline"
	defaultMountDir    = "/tmp/easyenclave-config-drive"
)

type Source string

const (
	SourceFile       Source = "file"
	SourceConfigISO  Source = "config-drive"
	SourceCmdline    Source = "cmdline"
	SourceDefault    Source = "default"
	defaultAgentMode        = "agent"
)

type Loader struct {
	ConfigPaths        []string
	ConfigDriveDevices []string
	ConfigDriveMount   string
	CmdlinePath        string
}

func DefaultLoader() Loader {
	paths := []string{}
	if envPath := strings.TrimSpace(os.Getenv("EASYENCLAVE_CONFIG")); envPath != "" {
		paths = append(paths, envPath)
	}
	paths = append(paths, defaultConfigPath)

	devices := []string{}
	if envDev := strings.TrimSpace(os.Getenv("EASYENCLAVE_CONFIG_DRIVE")); envDev != "" {
		devices = append(devices, envDev)
	}
	devices = append(devices, "/dev/sr0", "/dev/sr1", "/dev/cdrom", "/dev/cdrom0")

	return Loader{
		ConfigPaths:        paths,
		ConfigDriveDevices: devices,
		ConfigDriveMount:   defaultMountDir,
		CmdlinePath:        defaultCmdlinePath,
	}
}

func (l Loader) Load() (map[string]any, Source, error) {
	if cfg, ok, err := l.loadFromFilePaths(); err != nil {
		return nil, SourceDefault, err
	} else if ok {
		return cfg, SourceFile, nil
	}

	if cfg, ok, err := l.loadFromConfigDrive(); err != nil {
		return nil, SourceDefault, err
	} else if ok {
		return cfg, SourceConfigISO, nil
	}

	if cfg, ok, err := l.loadFromCmdline(); err != nil {
		return nil, SourceDefault, err
	} else if ok {
		return cfg, SourceCmdline, nil
	}

	return map[string]any{"mode": defaultAgentMode}, SourceDefault, nil
}

func (l Loader) loadFromFilePaths() (map[string]any, bool, error) {
	for _, p := range l.ConfigPaths {
		path := strings.TrimSpace(p)
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		cfg, err := readJSON(path)
		if err != nil {
			return nil, false, fmt.Errorf("read config file %s: %w", path, err)
		}
		return cfg, true, nil
	}
	return nil, false, nil
}

func (l Loader) loadFromConfigDrive() (map[string]any, bool, error) {
	mountDir := strings.TrimSpace(l.ConfigDriveMount)
	if mountDir == "" {
		mountDir = defaultMountDir
	}

	if cfg, ok, err := readConfigJSONInDir(mountDir); err != nil {
		return nil, false, err
	} else if ok {
		return cfg, true, nil
	}

	if err := os.MkdirAll(mountDir, 0o755); err != nil {
		return nil, false, fmt.Errorf("create config-drive mount dir: %w", err)
	}

	for _, dev := range l.ConfigDriveDevices {
		dev = strings.TrimSpace(dev)
		if dev == "" {
			continue
		}
		if _, err := os.Stat(dev); err != nil {
			continue
		}
		mountCmd := exec.Command("mount", "-o", "ro", dev, mountDir)
		if err := mountCmd.Run(); err != nil {
			continue
		}

		cfg, ok, err := readConfigJSONInDir(mountDir)
		_ = exec.Command("umount", mountDir).Run()
		if err != nil {
			return nil, false, err
		}
		if ok {
			return cfg, true, nil
		}
	}
	return nil, false, nil
}

func (l Loader) loadFromCmdline() (map[string]any, bool, error) {
	cmdlinePath := strings.TrimSpace(l.CmdlinePath)
	if cmdlinePath == "" {
		cmdlinePath = defaultCmdlinePath
	}
	raw, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return nil, false, nil
	}
	cmdline := strings.TrimSpace(string(raw))
	if cmdline == "" {
		return nil, false, nil
	}

	parts := strings.Fields(cmdline)
	for _, key := range []struct {
		prefix     string
		compressed bool
	}{
		{prefix: "easyenclave.configz=", compressed: true},
		{prefix: "easyenclave.config=", compressed: false},
	} {
		for _, part := range parts {
			if !strings.HasPrefix(part, key.prefix) {
				continue
			}
			encoded := strings.TrimPrefix(part, key.prefix)
			decoded, err := decodeB64Auto(encoded)
			if err != nil {
				return nil, false, fmt.Errorf("decode %s: %w", key.prefix, err)
			}
			if key.compressed {
				decoded, err = decompressZlib(decoded)
				if err != nil {
					return nil, false, fmt.Errorf("decompress %s: %w", key.prefix, err)
				}
			}
			var cfg map[string]any
			if err := json.Unmarshal(decoded, &cfg); err != nil {
				return nil, false, fmt.Errorf("parse %s json: %w", key.prefix, err)
			}
			return cfg, true, nil
		}
	}

	return nil, false, nil
}

func readConfigJSONInDir(dir string) (map[string]any, bool, error) {
	cfgPath := filepath.Join(dir, "config.json")
	info, err := os.Stat(cfgPath)
	if err != nil || info.IsDir() {
		return nil, false, nil
	}
	cfg, err := readJSON(cfgPath)
	if err != nil {
		return nil, false, fmt.Errorf("read config-drive %s: %w", cfgPath, err)
	}
	return cfg, true, nil
}

func readJSON(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func decodeB64Auto(in string) ([]byte, error) {
	if in == "" {
		return nil, errors.New("empty base64 payload")
	}
	padded := in + strings.Repeat("=", (4-len(in)%4)%4)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		raw, err := enc.DecodeString(padded)
		if err == nil {
			return raw, nil
		}
	}
	return nil, errors.New("invalid base64 payload")
}

func decompressZlib(in []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(in))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}
