package home

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// EnvHome is the preferred data-dir override for this fork (isolated from upstream grok).
	EnvHome = "XAI_HOME"
	// EnvHomeLegacy is accepted for compatibility with older env snippets.
	EnvHomeLegacy = "GROK_HOME"
	// DirName is the default directory under $HOME when no env override is set.
	// Intentionally NOT ".grok" so a side-by-side install cannot clobber upstream data.
	DirName = ".xai"
)

// Paths holds all filesystem locations under the data home.
type Paths struct {
	Root      string
	Config    string
	PID       string
	Lock      string
	State     string
	LogsDir   string
	Outputs   string
	Clearance string // optional: bundled compose path override
}

func Resolve() (Paths, error) {
	root := strings.TrimSpace(os.Getenv(EnvHome))
	if root == "" {
		root = strings.TrimSpace(os.Getenv(EnvHomeLegacy))
	}
	if root == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return Paths{}, err
		}
		root = filepath.Join(h, DirName)
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return Paths{}, err
	}
	p := Paths{
		Root:    root,
		Config:  filepath.Join(root, "config.env"),
		PID:     filepath.Join(root, "run.pid"),
		Lock:    filepath.Join(root, "run.lock"),
		State:   filepath.Join(root, "state.json"),
		LogsDir: filepath.Join(root, "logs"),
		Outputs: filepath.Join(root, "outputs"),
	}
	return p, nil
}

func (p Paths) EnsureBase() error {
	for _, d := range []string{p.Root, p.LogsDir, p.Outputs} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// NewRunID returns yyyymmdd-HHMMSS in local time.
func NewRunID() string {
	return time.Now().Format("20060102-150405")
}

// RunDirs is created before the first credential file is written.
type RunDirs struct {
	RunID     string
	Root      string
	SSO       string
	CPA       string
	SUB       string // Sub2API-compatible OAuth JSON
	Grok2API  string // SSO tokens + auth/*.json for grok2api importers
	Discarded string
	LogPath   string
}

func (p Paths) PrepareRun(runID string) (RunDirs, error) {
	if runID == "" {
		runID = NewRunID()
	}
	root := filepath.Join(p.Outputs, runID)
	rd := RunDirs{
		RunID:     runID,
		Root:      root,
		SSO:       filepath.Join(root, "SSO"),
		CPA:       filepath.Join(root, "CPA"),
		SUB:       filepath.Join(root, "SUB"),
		Grok2API:  filepath.Join(root, "grok2api"),
		Discarded: filepath.Join(root, "discarded"),
		LogPath:   filepath.Join(p.LogsDir, fmt.Sprintf("run-%s.log", runID)),
	}
	for _, d := range []string{rd.Root, rd.SSO, rd.CPA, rd.SUB, rd.Grok2API, rd.Discarded} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return RunDirs{}, err
		}
	}
	return rd, nil
}
