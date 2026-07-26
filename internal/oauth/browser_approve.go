package oauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var errBrowserApprovalUnavailable = errors.New("browser device approval unavailable")

// Confirm authorizes a device code through the real consent page when the
// Playwright helper is installed. Direct form posting remains a fallback for
// minimal installations, but the live page is authoritative because its
// client-side flow populates consent state that a synthetic POST can miss.
func (c *Client) Confirm(ctx context.Context, sso string, flow DeviceFlow) error {
	err := c.confirmBrowser(ctx, sso, flow)
	if err == nil {
		c.ClearRateLimit()
		return nil
	}
	if errors.Is(err, errBrowserApprovalUnavailable) {
		return c.ConfirmHTTP(ctx, sso, flow)
	}
	return err
}

func (c *Client) confirmBrowser(ctx context.Context, sso string, flow DeviceFlow) error {
	sso = strings.TrimSpace(sso)
	if sso == "" {
		return fmt.Errorf("login_required")
	}
	script := detectApprovalScript()
	python := detectApprovalPython()
	if script == "" || python == "" {
		return errBrowserApprovalUnavailable
	}
	if strings.TrimSpace(flow.VerificationURL) == "" || strings.TrimSpace(flow.UserCode) == "" {
		return fmt.Errorf("browser device approval: incomplete device flow")
	}

	timeout := 90 * time.Second
	if flow.ExpiresIn > 0 {
		expires := time.Duration(flow.ExpiresIn) * time.Second
		if expires < timeout {
			timeout = expires
		}
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout+5*time.Second)
		defer cancel()
	}

	args := []string{
		script,
		"--url", flow.VerificationURL,
		"--timeout", fmt.Sprintf("%.0f", timeout.Seconds()),
		"--ua", c.ua,
	}
	if proxy := strings.TrimSpace(c.proxy); proxy != "" {
		args = append(args, "--proxy", proxy)
	}
	bin, binArgs := approvalCommand(python, args)
	cmd := exec.CommandContext(ctx, bin, binArgs...)
	cmd.Stdin = strings.NewReader(sso + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("browser device approval: %s", truncateApprovalError(msg, 300))
	}
	if strings.TrimSpace(stdout.String()) != "ok" {
		return fmt.Errorf("browser device approval: unexpected helper output")
	}
	return nil
}

func detectApprovalPython() string {
	for _, key := range []string{"XAI_PYTHON", "GROK_PYTHON"} {
		if path := strings.TrimSpace(os.Getenv(key)); executableFile(path) {
			return path
		}
	}
	for _, path := range []string{
		"/opt/xai-cloakbrowser-venv/bin/python",
		"/opt/cloakbrowser-venv/bin/python",
	} {
		if executableFile(path) {
			return path
		}
	}
	if path, err := exec.LookPath("python3"); err == nil {
		return path
	}
	return ""
}

func detectApprovalScript() string {
	for _, key := range []string{"XAI_OAUTH_APPROVE_SCRIPT", "GROK_OAUTH_APPROVE_SCRIPT"} {
		if path := strings.TrimSpace(os.Getenv(key)); regularFile(path) {
			return path
		}
	}
	candidates := []string{
		"/usr/local/share/xai-reg/oauth_device_approve.py",
		"/opt/XAI-Register/scripts/oauth_device_approve.py",
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "oauth_device_approve.py"),
			filepath.Join(dir, "scripts", "oauth_device_approve.py"),
			filepath.Join(dir, "..", "scripts", "oauth_device_approve.py"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "scripts", "oauth_device_approve.py"))
	}
	for _, path := range candidates {
		if regularFile(path) {
			if abs, err := filepath.Abs(path); err == nil {
				return abs
			}
			return path
		}
	}
	return ""
}

func approvalCommand(python string, args []string) (string, []string) {
	if strings.TrimSpace(os.Getenv("DISPLAY")) != "" || strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) != "" {
		return python, args
	}
	if value := strings.ToLower(strings.TrimSpace(os.Getenv("XAI_OAUTH_NO_XVFB"))); value == "1" || value == "true" {
		return python, args
	}
	xvfb, err := exec.LookPath("xvfb-run")
	if err != nil {
		return python, args
	}
	wrapped := []string{"-a", python}
	wrapped = append(wrapped, args...)
	return xvfb, wrapped
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func executableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

func truncateApprovalError(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}
