package arp

import (
	"bytes"
	"context"
	"os/exec"
	"regexp"
)

const (
	withTargets = iota
	withLocalnet
	template = "(([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\t([^\n]*)\t([^\n]*))"
)

// Scanner represents an arp-scanner scan.
type Scanner struct {
	ctx    context.Context
	regexp *regexp.Regexp

	argsState int
	args      []string

	binaryPath string
}

func (s *Scanner) WithTargets(targets ...string) (*Scanner, error) {
	if s.argsState == withLocalnet {
		return s, ErrFlags
	}
	s.args = append(s.args, targets...)
	s.argsState = withTargets
	return s, nil
}

func (s *Scanner) WithLocalnet() (*Scanner, error) {
	if s.argsState == withTargets {
		return s, ErrFlags
	}
	s.args = append(s.args, "--localnet")
	s.argsState = withLocalnet
	return s, nil
}

func (s *Scanner) Run(ctx context.Context) (err error) {
	var stdout, stderr bytes.Buffer

	cmd := exec.Command(s.binaryPath, s.args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Start()
	if err != nil {
		return
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	select {
	case <-s.ctx.Done():
		_ = cmd.Process.Kill()
		err = ErrScanTimeout
		return
	case <-done:
		return
	}
}

// NewScanner returns arp scanner
func NewScanner() (scanner *Scanner, err error) {
	scanner = &Scanner{}
	scanner.binaryPath, err = exec.LookPath("arp-scan")
	if err != nil {
		err = ErrArpScanNotInstalled
		return
	}

	scanner.regexp, err = regexp.Compile(template)
	if err != nil {
		err = ErrRegexpCompile
		return
	}

	if scanner.ctx == nil {
		scanner.ctx = context.Background()
	}
	return
}
