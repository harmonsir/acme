// -ldflags "-w -s" -gcflags "-N -l"
package main

import (
	"fmt"
	"time"

	"github.com/harmonsir/acme/cmd"
)

func main() {
	next := time.Now()
	next = next.Add(3 * time.Second)

	ticker := time.Tick(time.Until(next))
	for range ticker {
		// call your function or run your task here
		cmd.EntryPoint()

		next = next.AddDate(0, 1, 0)
		next = time.Date(next.Year(), next.Month(), 1, 0, 0, 0, 0, next.Location())
		fmt.Println("Next run:", next)
	}
}
