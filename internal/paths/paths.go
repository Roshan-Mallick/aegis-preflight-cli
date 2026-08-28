package paths

import (
	"os"
	"path/filepath"
	"sort"
	"time"
)

func StateDir() string {
	if v := os.Getenv("AEGIS_STATE_DIR"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "aegis")
	}
	return filepath.Join(home, ".local", "state", "aegis")
}

func SessionsDir() string {
	return filepath.Join(StateDir(), "sessions")
}

func EnsureSessionsDir() (string, error) {
	dir := SessionsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func ListSessions() ([]string, error) {
	root := SessionsDir()
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	type item struct {
		id    string
		modAt time.Time
	}
	var items []item
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		info, err := ent.Info()
		if err != nil {
			continue
		}
		items = append(items, item{id: ent.Name(), modAt: info.ModTime()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].modAt.After(items[j].modAt) })
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.id)
	}
	return out, nil
}

func LatestSession() (string, error) {
	ids, err := ListSessions()
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", os.ErrNotExist
	}
	return ids[0], nil
}
