package main

import (
	"fmt"

	scanner "github.com/geoirb/net-scanner"
)

func main() {
	scan := scanner.NewNetScanner().
		WithTargets("192.168.0.106/24").
		WithPingScan()

	scan.Configurate()
	fmt.Println(scan.Scan())
}
