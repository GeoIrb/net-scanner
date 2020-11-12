package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/ullaakut/nmap"
)

// NetScanner net-scanner
type NetScanner struct {
	timeout      time.Duration
	targets      []string
	withPingScan bool
	ports        []string

	nmapScanner *nmap.Scanner

	mutex sync.RWMutex
	state map[string][]uint16
}

// WithTargets sets the target of a scanner.
func (s *NetScanner) WithTargets(targets ...string) *NetScanner {
	s.targets = targets
	return s
}

// WithPorts sets the ports which the scanner should scan on each host.
func (s *NetScanner) WithPorts(ports ...string) *NetScanner {
	s.ports = ports
	return s
}

// WithPingScan sets the discovery mode to simply ping the targets to scan and not scan them and disables DNS resolution in the discovery
// step of the nmap scan.
func (s *NetScanner) WithPingScan() *NetScanner {
	s.withPingScan = true
	return s
}

// Configurate scanner
func (s *NetScanner) Configurate() (err error) {
	options := []func(*nmap.Scanner){}

	if len(s.targets) != 0 {
		options = append(options, nmap.WithTargets(s.targets...))
	}

	if s.withPingScan {
		options = append(options, nmap.WithPingScan(), nmap.WithDisabledDNSResolution())
	} else {
		if len(s.ports) != 0 {
			options = append(options, nmap.WithPorts(s.ports...))
		}
	}

	s.nmapScanner, err = nmap.NewScanner(options...)
	return
}

// Scan network
func (s *NetScanner) Scan() (state map[string][]uint16, events []Event, err error) {
	if s.nmapScanner == nil {
		if err = s.Configurate(); err != nil {
			return
		}
	}

	result, _, err := s.nmapScanner.Run()
	if err != nil {
		return
	}

	state = s.parse(result)
	events = s.compare(state)

	s.mutex.Lock()
	s.state = state
	s.mutex.Unlock()
	return
}

// GetState after last scan
func (s *NetScanner) GetState() (state map[string][]uint16) {
	s.mutex.RLock()
	state = s.state
	s.mutex.RUnlock()
	return
}

// Run periodic scanning
// state - first state of network
// events - channel for events
func (s *NetScanner) Run(ctx context.Context) (state map[string][]uint16, events <-chan []Event, err error) {
	if err = s.Configurate(); err != nil {
		return
	}
	if state, _, err = s.Scan(); err != nil {
		return
	}

	eventCh := make(chan []Event)
	go func() {
		tick := time.NewTicker(s.timeout)
		defer func() {
			close(eventCh)
			tick.Stop()
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				_, events, err := s.Scan()
				if err != nil {
					return
				}
				if events != nil {
					eventCh <- events
				}
			}
		}
	}()
	events = eventCh
	return
}

func (s *NetScanner) parse(result *nmap.Run) (state map[string][]uint16) {
	state = make(map[string][]uint16)
	for _, host := range result.Hosts {
		ports := make([]uint16, 0, len(host.Ports))
		for _, port := range host.Ports {
			if port.State.String() == "open" {
				ports = append(ports, port.ID)
			}
		}
		if len(ports) != 0 || s.withPingScan {
			state[host.Addresses[0].String()] = ports
		}
	}

	return
}

func (s *NetScanner) compare(state map[string][]uint16) (events []Event) {
	for host := range state {
		if _, isExist := s.state[host]; !isExist {
			events = append(events,
				Event{
					Type: TurnOnHostEvent,
					Host: host,
				})
		}
	}
	for host := range s.state {
		if _, isExist := state[host]; !isExist {
			events = append(events,
				Event{
					Type: TurnOffHostEvent,
					Host: host,
				})
		}
	}
	return
}

// NewNetScanner ...
// timeout is period of scan network
func NewNetScanner(timeout time.Duration) *NetScanner {
	return &NetScanner{
		timeout: timeout,
	}
}
