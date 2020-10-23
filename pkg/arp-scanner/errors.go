package arp

import "errors"

var (
	// ErrArpScanNotInstalled means that upon trying to manually locate arp-scan in the user's path,
	// it was not found.
	// resolve: 	sudo apt install arp-scanner
	ErrArpScanNotInstalled = errors.New("arp-scan ner binary was not found")
	// ErrRegexpCompile means that trying to compile regexp template is not possible
	ErrRegexpCompile = errors.New("regexp template is not compiled")
	ErrFlags         = errors.New("should not specify targets with the --localnet option")
	// ErrScanTimeout means that the provided context was done before the scanner finished its scan.
	ErrScanTimeout = errors.New("arp-scan scan timed out")
)
