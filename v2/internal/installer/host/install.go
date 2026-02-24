package host

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type Config struct {
	AgentSourcePath string
	InstallRoot     string
	ServiceName     string
	SystemdDir      string
	EnvDir          string
	AgentUser       string
	AgentGroup      string
	AgentArgs       []string
	EnvVars         map[string]string
	SkipSystemd     bool
	DryRun          bool
	RunAgentNow     bool
}

func DefaultConfig() Config {
	return Config{
		InstallRoot: "/opt/easyenclave",
		ServiceName: "easyenclave-agent",
		SystemdDir:  "/etc/systemd/system",
		EnvDir:      "/etc/easyenclave",
		AgentUser:   "root",
		AgentGroup:  "root",
		EnvVars: map[string]string{
			"EASYENCLAVE_CONFIG": "/etc/easyenclave/config.json",
		},
	}
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.AgentSourcePath) == "" {
		return errors.New("missing agent source path")
	}
	if strings.TrimSpace(c.InstallRoot) == "" {
		return errors.New("missing install root")
	}
	if strings.TrimSpace(c.ServiceName) == "" {
		return errors.New("missing service name")
	}
	if strings.TrimSpace(c.SystemdDir) == "" {
		return errors.New("missing systemd dir")
	}
	if strings.TrimSpace(c.EnvDir) == "" {
		return errors.New("missing env dir")
	}
	return nil
}

func (c Config) AgentInstallPath() string {
	return filepath.Join(c.InstallRoot, "bin", "agent")
}

func (c Config) EnvFilePath() string {
	return filepath.Join(c.EnvDir, "agent.env")
}

func (c Config) ServiceFilePath() string {
	return filepath.Join(c.SystemdDir, c.ServiceName+".service")
}

type Installer struct {
	cfg Config
}

func New(cfg Config) (*Installer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Installer{cfg: cfg}, nil
}

func (i *Installer) Install() error {
	if err := os.MkdirAll(filepath.Join(i.cfg.InstallRoot, "bin"), 0o755); err != nil {
		return fmt.Errorf("create install bin dir: %w", err)
	}
	if err := os.MkdirAll(i.cfg.SystemdDir, 0o755); err != nil {
		return fmt.Errorf("create systemd dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(i.cfg.EnvFilePath()), 0o755); err != nil {
		return fmt.Errorf("create env dir: %w", err)
	}

	if err := copyFile(i.cfg.AgentSourcePath, i.cfg.AgentInstallPath(), 0o755); err != nil {
		return fmt.Errorf("install agent binary: %w", err)
	}
	if err := os.WriteFile(i.cfg.EnvFilePath(), []byte(RenderEnvFile(i.cfg.EnvVars)), 0o644); err != nil {
		return fmt.Errorf("write env file: %w", err)
	}
	if err := os.WriteFile(i.cfg.ServiceFilePath(), []byte(RenderSystemdUnit(i.cfg)), 0o644); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}

	if i.cfg.SkipSystemd || i.cfg.DryRun {
		if i.cfg.RunAgentNow && !i.cfg.DryRun {
			return i.RunInstalledAgent()
		}
		return nil
	}

	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "--now", i.cfg.ServiceName+".service"); err != nil {
		return err
	}
	return nil
}

func (i *Installer) RunInstalledAgent() error {
	cmd := exec.Command(i.cfg.AgentInstallPath(), i.cfg.AgentArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	for k, v := range i.cfg.EnvVars {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run installed agent: %w", err)
	}
	return nil
}

func RenderSystemdUnit(cfg Config) string {
	args := ""
	if len(cfg.AgentArgs) > 0 {
		args = " " + strings.Join(cfg.AgentArgs, " ")
	}
	return fmt.Sprintf(`[Unit]
Description=EasyEnclave Agent Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%s
Group=%s
WorkingDirectory=%s
EnvironmentFile=-%s
ExecStart=%s%s
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, defaultIfEmpty(cfg.AgentUser, "root"), defaultIfEmpty(cfg.AgentGroup, "root"), cfg.InstallRoot, cfg.EnvFilePath(), cfg.AgentInstallPath(), args)
}

func RenderEnvFile(env map[string]string) string {
	if len(env) == 0 {
		return ""
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v := env[k]
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(shellEscapeEnv(v))
		b.WriteByte('\n')
	}
	return b.String()
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run %s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func defaultIfEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func shellEscapeEnv(v string) string {
	if v == "" {
		return `""`
	}
	escaped := strings.ReplaceAll(v, `"`, `\"`)
	return `"` + escaped + `"`
}
