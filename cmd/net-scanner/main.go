package main

import (
	"fmt"
	"log"

	"github.com/Ullaakut/nmap"
)

func main() {
	s, err := nmap.NewScanner(
		nmap.WithTargets("192.168.0.1/24"),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	scanResult, _, err := s.Run()
	if err != nil {
		log.Fatalf("nmap encountered an error: %v", err)
	}

	fmt.Println(scanResult.Args)

	for _, host := range scanResult.Hosts {
		fmt.Println(host.Addresses)
	}
}
