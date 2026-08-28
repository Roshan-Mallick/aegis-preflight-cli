package observer

import (
	"bufio"
	"context"
	"os"
	"sync"
	"time"

	"github.com/eth0x1/aegis/internal/events"
)

type Tailer struct {
	path     string
	store    *events.Store
	feed     *Feed
	onEvent  func(events.Event)
	mu       sync.Mutex
	offset   int64
	partial  []byte
	stopped  bool
	injected int
	rejected int
}

func StartTailer(path string, store *events.Store, feed *Feed) *Tailer {
	t := &Tailer{path: path, store: store, feed: feed}
	return t
}

func (t *Tailer) SetOnEvent(fn func(events.Event)) {
	t.mu.Lock()
	t.onEvent = fn
	t.mu.Unlock()
}

func (t *Tailer) Stats() (injected, rejected int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.injected, t.rejected
}

func (t *Tailer) Stop() {
	t.mu.Lock()
	t.stopped = true
	t.mu.Unlock()
}

func (t *Tailer) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.drain()
			return
		case <-ticker.C:
			t.mu.Lock()
			stopped := t.stopped
			t.mu.Unlock()
			if stopped {
				t.drain()
				return
			}
			t.drain()
		}
	}
}

func (t *Tailer) drain() {
	f, err := os.Open(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		return
	}
	defer f.Close()
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, err := f.Seek(t.offset, 0); err != nil {
		return
	}
	sc := bufio.NewReader(f)
	if len(t.partial) > 0 {
		line, err := sc.ReadBytes('\n')
		chunk := append(t.partial, line...)
		if err != nil && len(chunk) > 0 && chunk[len(chunk)-1] != '\n' {
			t.partial = chunk
			return
		}
		t.partial = nil
		t.consume(chunk)
		t.offset += int64(len(line))
	}
	for {
		line, rerr := sc.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			t.consume(line)
			t.offset += int64(len(line))
			continue
		}
		if len(line) > 0 {
			t.partial = append([]byte{}, line...)
		}
		_ = rerr
		break
	}
}

func (t *Tailer) consume(line []byte) {
	trimmed := trimSpace(line)
	if len(trimmed) == 0 {
		return
	}
	ev, ok := NormalizeHook(trimmed)
	if !ok {
		t.rejected++
		return
	}
	if t.store != nil {
		if err := t.store.Append(ev); err != nil {
			t.rejected++
			return
		}
	}
	t.injected++
	if t.feed != nil {
		t.feed.Publish(ev)
	}
	if t.onEvent != nil {
		t.onEvent(ev)
	}
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\r' || b[0] == '\n') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\r' || b[len(b)-1] == '\n') {
		b = b[:len(b)-1]
	}
	return b
}

type Feed struct {
	mu       sync.Mutex
	ring     []events.Event
	next     int
	count    int
	subs     map[chan events.Event]struct{}
	capacity int
}

func NewFeed(capacity int) *Feed {
	if capacity <= 0 {
		capacity = 500
	}
	return &Feed{
		ring:     make([]events.Event, capacity),
		subs:     make(map[chan events.Event]struct{}),
		capacity: capacity,
	}
}

func (f *Feed) Publish(e events.Event) {
	f.mu.Lock()
	f.ring[f.next] = e
	f.next = (f.next + 1) % f.capacity
	if f.count < f.capacity {
		f.count++
	}
	for ch := range f.subs {
		select {
		case ch <- e:
		default:
		}
	}
	f.mu.Unlock()
}

func (f *Feed) Subscribe() chan events.Event {
	ch := make(chan events.Event, 128)
	f.mu.Lock()
	f.subs[ch] = struct{}{}
	f.mu.Unlock()
	return ch
}

func (f *Feed) Unsubscribe(ch chan events.Event) {
	f.mu.Lock()
	delete(f.subs, ch)
	f.mu.Unlock()
	close(ch)
}

func (f *Feed) Snapshot() []events.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]events.Event, 0, f.count)
	start := (f.next - f.count + f.capacity) % f.capacity
	for i := 0; i < f.count; i++ {
		out = append(out, f.ring[(start+i)%f.capacity])
	}
	return out
}

func FollowJSONL(ctx context.Context, path string, interval time.Duration, fn func(line []byte)) {
	var offset int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		if _, err := f.Seek(offset, 0); err != nil {
			f.Close()
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		moved := offset
		for sc.Scan() {
			line := sc.Bytes()
			moved += int64(len(line)) + 1
			b := make([]byte, len(line))
			copy(b, line)
			fn(b)
		}
		offset = moved
		f.Close()
	}
}
