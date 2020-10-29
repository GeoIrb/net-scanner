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
	withListScan bool
	ports        []string

	nmapScanner *nmap.Scanner

	mutex sync.RWMutex
	state map[string][]uint16
}

func (s *NetScanner) WithTargets(targets ...string) *NetScanner {
	s.targets = targets
	return s
}

func (s *NetScanner) WithPorts(ports ...string) *NetScanner {
	s.ports = ports
	return s
}

func (s *NetScanner) WithListScan() *NetScanner {
	s.withListScan = true
	return s
}

func (s *NetScanner) Configurate() (err error) {
	options := []func(*nmap.Scanner){}

	if len(s.targets) != 0 {
		options = append(options, nmap.WithTargets(s.targets...))
	}

	if s.withListScan {
		options = append(options, nmap.WithListScan())
	} else {
		if len(s.ports) != 0 {
			options = append(options, nmap.WithPorts(s.ports...))
		}
	}

	s.nmapScanner, err = nmap.NewScanner(options...)
	return
}

func (s *NetScanner) Scan() (state map[string][]uint16, events []Event, err error) {
	if s.nmapScanner == nil {
		return
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

func (s *NetScanner) GetState() (state map[string][]uint16) {
	s.mutex.RLock()
	state = s.state
	s.mutex.RUnlock()
	return
}

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
			ports = append(ports, port.ID)
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

func NewNetScanner() *NetScanner {
	return &NetScanner{}
}
