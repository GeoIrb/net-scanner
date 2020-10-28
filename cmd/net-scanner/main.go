package main

import (
	"fmt"

	interfaces "github.com/geoirb/net-scanner/pkg/net-interfaces"
	"github.com/geoirb/net-scanner/pkg/nmap"
)

func main() {
	i := interfaces.NewNetInterfaces()
	ips, _ := i.GetIP("enp4s0")

	s := nmap.NewScanner()
	fmt.Println(s.Scan([]string{ips[0]}, []string{}))
}
