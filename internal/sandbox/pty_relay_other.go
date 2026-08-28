//go:build !linux

package sandbox

import (
	"io"
	"os"
)

func relayStdinToPTY(fd int, ptmx io.Writer, stop <-chan struct{}) error {
	go func() { io.Copy(ptmx, os.Stdin); stop <- struct{}{} }()
	<-stop
	return nil
}
