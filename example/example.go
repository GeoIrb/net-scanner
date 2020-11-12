package main

import (
	"context"
	"fmt"
	"time"

	scanner "github.com/geoirb/net-scanner"
)

func main() {
	scan := scanner.NewNetScanner(time.Minute).
		WithTargets("192.168.0.106/24").
		WithPingScan()

	scan.Configurate()
	state, events, err := scan.Run(context.Background())

	fmt.Println(state, err)
	e := <-events
	fmt.Println(e)
}
