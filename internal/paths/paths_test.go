package paths

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateDirEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("AEGIS_STATE_DIR", tmp)
	if got := StateDir(); got != tmp {
		t.Fatalf("StateDir = %s, want %s", got, tmp)
	}
	if got := SessionsDir(); got != filepath.Join(tmp, "sessions") {
		t.Fatalf("SessionsDir = %s", got)
	}
	dir, err := EnsureSessionsDir()
	if err != nil {
		t.Fatalf("EnsureSessionsDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() == false {
		t.Fatal("sessions dir not created")
	}
}

func TestListSessionsNewestFirst(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AEGIS_STATE_DIR", root)

	if ids, _ := ListSessions(); len(ids) != 0 {
		t.Fatal("expected no sessions initially")
	}

	if _, err := EnsureSessionsDir(); err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	os.MkdirAll(filepath.Join(SessionsDir(), "aaaa"), 0o700)
	os.MkdirAll(filepath.Join(SessionsDir(), "bbbb"), 0o700)
	future := filepath.Join(SessionsDir(), "cccc")
	os.MkdirAll(future, 0o700)
	os.Chtimes(future, base.Add(2*time.Second), base.Add(2*time.Second))

	ids, err := ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 {
		t.Fatalf("got %d sessions", len(ids))
	}
	if ids[0] != "cccc" {
		t.Fatalf("newest first violated: %v", ids)
	}

	latest, err := LatestSession()
	if err != nil || latest != "cccc" {
		t.Fatalf("LatestSession = %s, %v", latest, err)
	}
}
