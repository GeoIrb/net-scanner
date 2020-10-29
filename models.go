package scanner

const (
	// TurnOnHostEvent type of event means turn on host
	TurnOnHostEvent = iota
	// TurnOffHostEvent type of event means turn off host
	TurnOffHostEvent
)

// Event struct
type Event struct {
	Type string
	Host string
}
