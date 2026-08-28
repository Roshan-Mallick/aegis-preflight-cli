//go:build linux

package sandbox

import (
	"io"

	"golang.org/x/sys/unix"
)

// relayStdinToPTY copies bytes from the user's stdin (fd) into the PTY
// master until the session ends (stop closes) or the pipe breaks. It uses
// poll(2) with a bounded wait instead of a blocking read so the relay can
// never outlive the interactive session it belongs to; a relay that blocks
// forever on stdin would swallow keystrokes of a later remediation round.
func relayStdinToPTY(fd int, ptmx io.Writer, stop <-chan struct{}) error {
	pfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	buf := make([]byte, 4096)
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		n, perr := unix.Poll(pfds, 100)
		if perr != nil {
			if perr == unix.EINTR {
				continue
			}
			return perr
		}
		if n == 0 {
			continue
		}
		nr, rerr := unix.Read(fd, buf)
		if nr > 0 {
			if _, werr := ptmx.Write(buf[:nr]); werr != nil {
				return werr
			}
		}
		if rerr != nil {
			return rerr
		}
	}
}
