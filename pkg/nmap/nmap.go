package nmap

import (
	"fmt"

	"github.com/ullaakut/nmap"
)

type nmapScan struct{}

func (n *nmapScan) Scan(targets []string, ports []string) (hosts []string, err error) {
	s, err := nmap.NewScanner(
		nmap.WithTargets(targets...),
		nmap.WithPorts(ports...),
	)
	if err != nil {
		return
	}

	scanResult, _, err := s.Run()
	if err != nil {
		return
	}

	for _, host := range scanResult.Hosts {
		fmt.Println(host.Distance.Value)
	}
	return
}
