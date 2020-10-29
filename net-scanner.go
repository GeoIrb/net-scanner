package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/ullaakut/nmap"
)

// Scanner net-scanner
type Scanner struct {
	timeout      time.Duration
	targets      []string
	withListScan bool
	ports        []string

	nmapScanner *nmap.Scanner

	mutex sync.RWMutex
	state map[string][]uint16
}

func (s *Scanner) Configurate() (err error) {
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

func (s *Scanner) Scan() (state map[string][]uint16, err error) {
	if s.nmapScanner == nil {
		return
	}

	res, _, err := s.nmapScanner.Run()
	if err != nil {
		return
	}

	state = make(map[string][]uint16)
	for _, host := range res.Hosts {
		ports := make([]uint16, 0, len(host.Ports))
		for _, port := range host.Ports {
			ports = append(ports, port.ID)
		}
	}
	s.mutex.Lock()
	s.state = state
	s.mutex.Unlock()
	return
}

func (s *Scanner) GetState() (state map[string][]uint16) {
	s.mutex.RLock()
	state = s.state
	s.mutex.RUnlock()
	return
}

// Run ...
func (s *Scanner) Run(ctx context.Context) (state map[string][]uint16, events <-chan []Event, err error) {
	if err = s.Configurate(); err != nil {
		return
	}
	if state, err = s.Scan(); err != nil {
		return
	}

	eventCh := make(chan []Event)
	go func() {
		defer close(eventCh)
		tick := time.Tick(s.timeout)
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick:
				state, err := s.Scan()
				if err != nil {
					return
				}
				if events := s.compare(state); events != nil {
					eventCh <- events
				}
			}
		}
	}()
	events = eventCh
	return
}

func (s *Scanner) compare(state map[string][]uint16) (events []Event) {
	return
}
