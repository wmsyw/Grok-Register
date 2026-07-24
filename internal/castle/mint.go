// Package castle mints Castle request tokens for accounts.x.ai anti-abuse.
package castle

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DefaultPK is the public Castle publishable key used by accounts.x.ai.
const DefaultPK = "pk_p8GGWvD3TmFJZRsX3BQcqAv9aFVispNz"

// Options for Mint.
type Options struct {
	Python  string
	Script  string
	Proxy   string
	URL     string
	PK      string
	Cookie  string
	UA      string
	Mode    string // offscreen|headless|auto
	Timeout time.Duration
}

// Result of a Castle mint.
type Result struct {
	Token   string
	Cookies string // "a=b; c=d" from browser jar (CF/castle), no sso
}

// Mint runs scripts/castle_mint.py and returns a castleRequestToken.
func Mint(ctx context.Context, opt Options) (string, error) {
	res, err := MintFull(ctx, opt)
	if err != nil {
		return "", err
	}
	return res.Token, nil
}

// MintFull returns token + browser cookies for protocol session reuse.
func MintFull(ctx context.Context, opt Options) (Result, error) {
	script := strings.TrimSpace(opt.Script)
	if script == "" {
		script = detectScript()
	}
	if script == "" {
		return Result{}, fmt.Errorf("castle_mint.py not found; set XAI_CASTLE_SCRIPT or install scripts/")
	}
	py := strings.TrimSpace(opt.Python)
	if py == "" {
		py = firstEnv("XAI_PYTHON", "GROK_PYTHON")
	}
	if py == "" {
		py = "python3"
	}
	url := strings.TrimSpace(opt.URL)
	if url == "" {
		url = "https://accounts.x.ai/sign-up"
	}
	pk := strings.TrimSpace(opt.PK)
	if pk == "" {
		pk = firstEnv("CASTLE_PK", "XAI_CASTLE_PK")
	}
	if pk == "" {
		pk = DefaultPK
	}
	mode := strings.TrimSpace(opt.Mode)
	if mode == "" {
		mode = "offscreen"
	}
	to := opt.Timeout
	if to <= 0 {
		to = 60 * time.Second
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, to+5*time.Second)
		defer cancel()
	}

	args := []string{
		script,
		"--url", url,
		"--pk", pk,
		"--mode", mode,
		"--timeout", fmt.Sprintf("%.0f", to.Seconds()),
	}
	if p := strings.TrimSpace(opt.Proxy); p != "" {
		args = append(args, "--proxy", p)
	}
	if c := strings.TrimSpace(opt.Cookie); c != "" {
		args = append(args, "--cookie", c)
	}
	if ua := strings.TrimSpace(opt.UA); ua != "" {
		args = append(args, "--ua", ua)
	}

	bin, binArgs := maybeXvfb(py, args, mode)
	cmd := exec.CommandContext(ctx, bin, binArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return Result{}, fmt.Errorf("castle mint: %s", truncate(msg, 240))
	}
	tok := strings.TrimSpace(stdout.String())
	if i := strings.IndexAny(tok, "\r\n"); i >= 0 {
		tok = tok[:i]
	}
	if len(tok) < 20 {
		return Result{}, fmt.Errorf("castle mint: empty token")
	}
	return Result{Token: tok, Cookies: parseCookiesLine(stderr.String())}, nil
}

func parseCookiesLine(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "COOKIES:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "COOKIES:"))
		}
	}
	return ""
}

func detectScript() string {
	if p := firstEnv("XAI_CASTLE_SCRIPT", "GROK_CASTLE_SCRIPT"); p != "" {
		if fileExists(p) {
			return p
		}
	}
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "scripts", "castle_mint.py"),
			filepath.Join(dir, "castle_mint.py"),
			filepath.Join(dir, "..", "scripts", "castle_mint.py"),
			"/usr/local/share/xai-reg/castle_mint.py",
			"/opt/XAI-Register/scripts/castle_mint.py",
		)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "scripts", "castle_mint.py"))
	}
	for _, c := range candidates {
		if fileExists(c) {
			if abs, err := filepath.Abs(c); err == nil {
				return abs
			}
			return c
		}
	}
	return ""
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// maybeXvfb wraps python with xvfb-run when offscreen is requested and no DISPLAY.
func maybeXvfb(python string, args []string, mode string) (string, []string) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "auto" {
		mode = "offscreen"
	}
	if mode == "headless" {
		return python, args
	}
	if strings.TrimSpace(os.Getenv("DISPLAY")) != "" || strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) != "" {
		return python, args
	}
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("XAI_CASTLE_NO_XVFB"))); v == "1" || v == "true" {
		return python, args
	}
	xvfb, err := exec.LookPath("xvfb-run")
	if err != nil {
		return python, args
	}
	out := []string{"-a", python}
	out = append(out, args...)
	return xvfb, out
}
