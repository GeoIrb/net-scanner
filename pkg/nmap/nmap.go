package nmap

import (
	"github.com/ullaakut/nmap"
)

// Scanner ...
type Scanner struct{}

// Scan ...
func (n *Scanner) Scan(targets []string, ports []string) (hosts map[string][]uint16, err error) {
	options := []func(*nmap.Scanner){}

	if len(targets) != 0 {
		options = append(options, nmap.WithTargets(targets...))
	}

	if len(ports) != 0 {
		options = append(options, nmap.WithPorts(ports...))
	}

	s, err := nmap.NewScanner(
		options...,
	)
	if err != nil {
		return
	}

	scanResult, _, err := s.Run()
	if err != nil {
		return
	}

	hosts = make(map[string][]uint16)
	for _, host := range scanResult.Hosts {
		ports := make([]uint16, 0, len(host.Ports))
		for _, p := range host.Ports {
			ports = append(ports, p.ID)
		}
		hosts[host.Addresses[0].String()] = ports
	}
	return
}

// NewScanner ...
func NewScanner() *Scanner {
	return &Scanner{}
}
