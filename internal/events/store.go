package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const logFileName = "events.jsonl"

func LogPath(sessionDir string) string {
	return filepath.Join(sessionDir, logFileName)
}

type Store struct {
	path string
	mu   sync.Mutex
	f    *os.File
}

func Open(sessionDir string) (*Store, error) {
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return nil, fmt.Errorf("create session dir: %w", err)
	}
	f, err := os.OpenFile(LogPath(sessionDir), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open event log: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, fmt.Errorf("enforce event log permissions: %w", err)
	}
	return &Store{path: LogPath(sessionDir), f: f}, nil
}

func (s *Store) Path() string { return s.path }

func (s *Store) Append(e Event) error {
	if err := e.Validate(); err != nil {
		return fmt.Errorf("refusing to append invalid event: %w", err)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	b = append(b, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(b); err != nil {
		return fmt.Errorf("append event: %w", err)
	}
	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

func ReadAll(sessionDir string) ([]Event, error) {
	f, err := os.Open(LogPath(sessionDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open event log: %w", err)
	}
	defer f.Close()

	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("%s:%d: malformed event json: %w", LogPath(sessionDir), lineNo, err)
		}
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("%s:%d: invalid event: %w", LogPath(sessionDir), lineNo, err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan event log: %w", err)
	}
	return out, nil
}
