package email

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

// IMAP mailbox entry (Gmail app password etc.).
type imapAccount struct {
	Email string
	Pass  string
}

// imapState is process-local pool state for EMAIL_MODE=imap.
type imapState struct {
	mu      sync.Mutex
	loaded  bool
	host    string
	port    string
	// single-inbox + plus-alias mode
	user string
	pass string
	plus bool
	// multi-account pool
	pool []imapAccount
	used map[string]struct{}
	file string
}

func (p *Provider) imapEnsure() error {
	p.imap.mu.Lock()
	defer p.imap.mu.Unlock()
	if p.imap.loaded {
		return nil
	}
	host := strings.TrimSpace(p.cfg.IMAPHost)
	if host == "" {
		host = "imap.gmail.com"
	}
	port := strings.TrimSpace(p.cfg.IMAPPort)
	if port == "" {
		port = "993"
	}
	p.imap.host = host
	p.imap.port = port
	p.imap.plus = p.cfg.IMAPPlus
	p.imap.user = strings.TrimSpace(p.cfg.IMAPUser)
	p.imap.pass = p.cfg.IMAPPass
	p.imap.file = strings.TrimSpace(p.cfg.IMAPPoolFile)
	p.imap.used = map[string]struct{}{}

	if p.imap.file != "" {
		if err := p.imapLoadPoolLocked(); err != nil {
			return err
		}
	} else if p.imap.user == "" || p.imap.pass == "" {
		return fmt.Errorf("imap: set IMAP_POOL_FILE (email:app_password 每行) 或 IMAP_USER+IMAP_PASS")
	}
	p.imap.loaded = true
	return nil
}

func (p *Provider) imapLoadPoolLocked() error {
	f, err := os.Open(p.imap.file)
	if err != nil {
		return fmt.Errorf("imap pool open: %w", err)
	}
	defer f.Close()
	// optional used sidecar
	usedPath := p.imap.file + ".used"
	if b, err := os.ReadFile(usedPath); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(strings.ToLower(line))
			if line != "" && !strings.HasPrefix(line, "#") {
				p.imap.used[line] = struct{}{}
			}
		}
	}
	sc := bufio.NewScanner(f)
	var pool []imapAccount
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		email, pass, ok := splitPoolLine(line)
		if !ok {
			continue
		}
		if _, dead := p.imap.used[strings.ToLower(email)]; dead {
			continue
		}
		pool = append(pool, imapAccount{Email: email, Pass: pass})
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if len(pool) == 0 {
		return fmt.Errorf("imap pool empty (file=%s used=%d)", p.imap.file, len(p.imap.used))
	}
	p.imap.pool = pool
	return nil
}

func splitPoolLine(line string) (email, pass string, ok bool) {
	// Prefer email|password (password may contain ':'); else email:password.
	var i int
	if j := strings.Index(line, "|"); j > 0 {
		i = j
	} else {
		i = strings.Index(line, ":")
	}
	if i <= 0 {
		return "", "", false
	}
	email = strings.TrimSpace(line[:i])
	pass = strings.TrimSpace(line[i+1:])
	if email == "" || pass == "" || !strings.Contains(email, "@") {
		return "", "", false
	}
	return email, pass, true
}

func (p *Provider) imapCreate(xaiPassword string) (Handle, error) {
	if err := p.imapEnsure(); err != nil {
		return Handle{}, err
	}
	p.imap.mu.Lock()
	defer p.imap.mu.Unlock()

	now := time.Now().Unix()
	// Pool mode: consume one full mailbox (recommended for Gmail).
	if len(p.imap.pool) > 0 || p.imap.file != "" {
		if len(p.imap.pool) == 0 {
			return Handle{}, fmt.Errorf("imap pool exhausted")
		}
		acc := p.imap.pool[0]
		p.imap.pool = p.imap.pool[1:]
		p.imap.used[strings.ToLower(acc.Email)] = struct{}{}
		_ = p.imapAppendUsedLocked(acc.Email)
		return Handle{
			Kind:      "imap",
			Email:     acc.Email,
			Password:  xaiPassword,
			Token:     acc.Pass, // IMAP password / app password
			Base:      p.imap.host + ":" + p.imap.port,
			Timestamp: now,
		}, nil
	}

	// Single inbox + plus alias: user+tag@domain
	user := p.imap.user
	pass := p.imap.pass
	email := user
	if p.imap.plus {
		local, domain, ok := strings.Cut(user, "@")
		if !ok || local == "" || domain == "" {
			return Handle{}, fmt.Errorf("imap: IMAP_USER must be full email for plus mode")
		}
		// strip existing plus
		if i := strings.Index(local, "+"); i >= 0 {
			local = local[:i]
		}
		tag := "oc" + randStr(10)
		email = fmt.Sprintf("%s+%s@%s", local, tag, domain)
	}
	return Handle{
		Kind:      "imap",
		Email:     email,
		Password:  xaiPassword,
		Token:     pass,
		Base:      p.imap.host + ":" + p.imap.port,
		// store login user in Tag when plus (actual IMAP login identity)
		Tag:       user,
		Timestamp: now,
	}, nil
}

func (p *Provider) imapAppendUsedLocked(email string) error {
	if p.imap.file == "" {
		return nil
	}
	path := p.imap.file + ".used"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && !os.IsExist(err) {
		// dir may be .
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.WriteString(f, strings.ToLower(strings.TrimSpace(email))+"\n")
	return err
}

func (p *Provider) imapFetch(h Handle) (string, error) {
	if err := p.imapEnsure(); err != nil {
		return "", err
	}
	loginUser := strings.TrimSpace(h.Tag)
	if loginUser == "" {
		loginUser = h.Email
	}
	pass := h.Token
	if pass == "" {
		return "", fmt.Errorf("imap: empty app password")
	}
	addr := h.Base
	if addr == "" {
		addr = p.imap.host + ":" + p.imap.port
	}

	c, err := client.DialTLS(addr, nil)
	if err != nil {
		return "", fmt.Errorf("imap dial: %w", err)
	}
	defer c.Logout()

	if err := c.Login(loginUser, pass); err != nil {
		return "", fmt.Errorf("imap login %s: %w", loginUser, err)
	}

	mbox, err := c.Select("INBOX", false)
	if err != nil {
		return "", fmt.Errorf("imap select: %w", err)
	}
	if mbox == nil || mbox.Messages == 0 {
		return "", nil
	}

	// Fetch last N messages (newest last in sequence for many servers; we take a window).
	const window = uint32(25)
	from := uint32(1)
	if mbox.Messages > window {
		from = mbox.Messages - window + 1
	}
	seq := new(imap.SeqSet)
	seq.AddRange(from, mbox.Messages)

	section := &imap.BodySectionName{}
	items := []imap.FetchItem{imap.FetchEnvelope, imap.FetchFlags, imap.FetchInternalDate, section.FetchItem()}
	ch := make(chan *imap.Message, 16)
	done := make(chan error, 1)
	go func() {
		done <- c.Fetch(seq, items, ch)
	}()

	var b strings.Builder
	target := strings.ToLower(strings.TrimSpace(h.Email))
	since := time.Unix(h.Timestamp, 0).Add(-2 * time.Minute)
	if h.Timestamp <= 0 {
		since = time.Now().Add(-30 * time.Minute)
	}

	for msg := range ch {
		if msg == nil {
			continue
		}
		if !msg.InternalDate.IsZero() && msg.InternalDate.Before(since) {
			continue
		}
		// Prefer messages addressed to our signup email (plus-alias / exact).
		if target != "" && msg.Envelope != nil {
			if !imapAddressMatch(msg.Envelope, target) {
				// still allow if body will be scanned — some forwarders rewrite To
				// but skip clearly other recipients when plus mode
				if strings.Contains(target, "+") {
					continue
				}
			}
		}
		if msg.Envelope != nil {
			fmt.Fprintf(&b, "SUBJECT %s\n", msg.Envelope.Subject)
		}
		r := msg.GetBody(section)
		if r != nil {
			raw, _ := io.ReadAll(io.LimitReader(r, 1<<20))
			b.Write(raw)
			b.WriteByte('\n')
		}
	}
	if err := <-done; err != nil {
		return "", fmt.Errorf("imap fetch: %w", err)
	}
	return b.String(), nil
}

func imapAddressMatch(env *imap.Envelope, target string) bool {
	if env == nil {
		return true
	}
	check := func(list []*imap.Address) bool {
		for _, a := range list {
			if a == nil {
				continue
			}
			addr := strings.ToLower(strings.TrimSpace(a.Address()))
			if addr == target || strings.Contains(addr, target) || strings.Contains(target, addr) {
				return true
			}
		}
		return false
	}
	if check(env.To) || check(env.Cc) || check(env.Bcc) {
		return true
	}
	// no recipients parsed — don't filter out
	if len(env.To)+len(env.Cc)+len(env.Bcc) == 0 {
		return true
	}
	return false
}
