package interfaces

import (
	"net"
)

// NetInterfaces work with network interfaces
type NetInterfaces struct{}

// Get names of exist network interfaces
func (n *NetInterfaces) Get() (names []string, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}

	names = make([]string, 0, len(interfaces))
	for _, i := range interfaces {
		names = append(names, i.Name)
	}
	return
}

// GetIP todo
func (n *NetInterfaces) GetIP(name string) (ips []string, err error) {
	i, err := net.InterfaceByName(name)
	if err != nil {
		return
	}

	addrs, err := i.Addrs()
	if err != nil {
		return
	}

	ips = make([]string, 0, len(addrs))
	for _, add := range addrs {
		if ip, ok := add.(*net.IPNet); ok {
			ips = append(ips, ip.String())
		}
	}
	return
}

// NewNetInterfaces ...
func NewNetInterfaces() *NetInterfaces {
	return &NetInterfaces{}
}
