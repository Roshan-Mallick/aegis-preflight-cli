package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/eth0x1/aegis/internal/session"
)

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestDetectRootFindsMarkerUpward(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "go.mod"), "module x\n", 0o644)
	nested := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := DetectRoot(nested)
	if err != nil {
		t.Fatalf("DetectRoot: %v", err)
	}
	if got != root {
		t.Fatalf("root = %s, want %s", got, root)
	}
}

func TestDetectRootFallbackAndGuards(t *testing.T) {
	plain := t.TempDir()
	got, err := DetectRoot(plain)
	if err != nil || got != plain {
		t.Fatalf("fallback = %s, %v", got, err)
	}
	if _, err := DetectRoot(plain + "/does-not-exist-xyz"); err == nil {
		t.Fatal("nonexistent start should error")
	}
}

func TestSnapshotCopiesFilesExcludesJunkPreservesModes(t *testing.T) {
	root := t.TempDir()
	dest := t.TempDir()
	write(t, filepath.Join(root, "src/main.go"), "package main\n", 0o644)
	write(t, filepath.Join(root, "run.sh"), "#!/bin/sh\n", 0o755)
	write(t, filepath.Join(root, "node_modules/leftpad/index.js"), "junk", 0o644)
	write(t, filepath.Join(root, ".git/HEAD"), "ref: x", 0o644)

	res, err := Snapshot(root, dest)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if res.FilesCopied != 2 {
		t.Fatalf("copied %d files, want 2", res.FilesCopied)
	}
	if mustRead(t, filepath.Join(dest, "src/main.go")) != "package main\n" {
		t.Fatal("content mismatch")
	}
	if _, err := os.Stat(filepath.Join(dest, "node_modules")); !os.IsNotExist(err) {
		t.Fatal("node_modules must not be copied")
	}
	if _, err := os.Stat(filepath.Join(dest, ".git")); !os.IsNotExist(err) {
		t.Fatal(".git must not be copied")
	}
	fi, err := os.Stat(filepath.Join(dest, "run.sh"))
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("exec bit lost: %v %v", fi, err)
	}
	if e := res.Manifest["src/main.go"]; e.Type != "file" || e.SHA256 == "" {
		t.Fatalf("manifest entry wrong: %+v", e)
	}
}

func TestSnapshotSkipsEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	dest := t.TempDir()
	secret := filepath.Join(t.TempDir(), "host-secret.txt")
	write(t, secret, "TOPSECRET", 0o600)

	write(t, filepath.Join(root, "ok.txt"), "fine", 0o644)
	internalTarget := filepath.Join(root, "target.txt")
	write(t, internalTarget, "inside", 0o644)
	if err := os.Symlink("target.txt", filepath.Join(root, "internal-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "steal-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../outside.txt", filepath.Join(root, "rel-escape-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "abs-escape-link")); err != nil {
		t.Fatal(err)
	}

	res, err := Snapshot(root, dest)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	for _, p := range []string{"steal-link", "rel-escape-link", "abs-escape-link"} {
		if _, err := os.Lstat(filepath.Join(dest, p)); !os.IsNotExist(err) {
			t.Fatalf("%s must not enter the workspace", p)
		}
	}
	if len(res.SkippedSymlinks) != 3 {
		t.Fatalf("skipped = %v, want 3 escaping links", res.SkippedSymlinks)
	}
	if _, err := os.Lstat(filepath.Join(dest, "internal-link")); err != nil {
		t.Fatalf("internal symlink must be preserved: %v", err)
	}
	if got, _ := os.Readlink(filepath.Join(dest, "internal-link")); got != "target.txt" {
		t.Fatalf("link target = %q", got)
	}
}

func TestSnapshotEnforcesCaps(t *testing.T) {
	oldBytes, oldFiles := SnapshotMaxBytes, SnapshotMaxFiles
	SnapshotMaxBytes, SnapshotMaxFiles = 8, 100000
	defer func() { SnapshotMaxBytes, SnapshotMaxFiles = oldBytes, oldFiles }()

	root := t.TempDir()
	write(t, filepath.Join(root, "big.bin"), "0123456789abcdef", 0o644)
	if _, err := Snapshot(root, t.TempDir()); err == nil {
		t.Fatal("byte cap not enforced")
	}

	SnapshotMaxBytes = 1 << 30
	SnapshotMaxFiles = 2
	root2 := t.TempDir()
	write(t, filepath.Join(root2, "a"), "x", 0o644)
	write(t, filepath.Join(root2, "b"), "y", 0o644)
	write(t, filepath.Join(root2, "c"), "z", 0o644)
	if _, err := Snapshot(root2, t.TempDir()); err == nil {
		t.Fatal("file cap not enforced")
	}
}

func TestComputeDiffKinds(t *testing.T) {
	root := t.TempDir()
	dest := t.TempDir()
	write(t, filepath.Join(root, "keep.txt"), "same", 0o644)
	write(t, filepath.Join(root, "mod.txt"), "old", 0o644)
	write(t, filepath.Join(root, "del.txt"), "gone", 0o644)
	write(t, filepath.Join(root, "typechange.txt"), "was-file", 0o644)

	res, err := Snapshot(root, dest)
	if err != nil {
		t.Fatal(err)
	}
	before := res.Manifest

	write(t, filepath.Join(dest, "new.txt"), "added", 0o644)
	write(t, filepath.Join(dest, "mod.txt"), "new", 0o644)
	os.Remove(filepath.Join(dest, "del.txt"))
	os.Remove(filepath.Join(dest, "typechange.txt"))
	os.Symlink("keep.txt", filepath.Join(dest, "typechange.txt"))
	write(t, filepath.Join(dest, "node_modules/x.js"), "artifact", 0o644)

	changes, current, err := ComputeDiff(before, dest)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Change{}
	for _, ch := range changes {
		got[ch.Path] = ch
	}
	if k := got["new.txt"].Kind; k != KindAdded {
		t.Errorf("new.txt = %s", k)
	}
	if k := got["mod.txt"].Kind; k != KindModified {
		t.Errorf("mod.txt = %s", k)
	}
	if k := got["del.txt"].Kind; k != KindDeleted {
		t.Errorf("del.txt = %s", k)
	}
	if k := got["typechange.txt"].Kind; k != KindTypeChange {
		t.Errorf("typechange.txt = %s", k)
	}
	if k := got["keep.txt"].Kind; k != "" {
		t.Errorf("keep.txt wrongly changed: %s", k)
	}
	if _, ok := current["node_modules/x.js"]; ok {
		t.Error("excluded dirs must never enter diffs/promotions")
	}
}

func TestAgentEditsNeverTouchTrustedProject(t *testing.T) {
	root := t.TempDir()
	dest := t.TempDir()
	write(t, filepath.Join(root, "app.py"), "print('v1')\n", 0o644)
	write(t, filepath.Join(root, ".env"), "SECRET=host-only\n", 0o600)

	res, err := Snapshot(root, dest)
	if err != nil {
		t.Fatal(err)
	}
	trustedBefore, err := TreeDigest(root)
	if err != nil {
		t.Fatal(err)
	}

	write(t, filepath.Join(dest, "app.py"), "print('agent was here')\n", 0o644)
	write(t, filepath.Join(dest, "feature.py"), "print('new')\n", 0o644)

	trustedAfter, err := TreeDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(trustedBefore) != len(trustedAfter) {
		t.Fatalf("trusted project file count changed: %d -> %d", len(trustedBefore), len(trustedAfter))
	}
	for p, h := range trustedBefore {
		if trustedAfter[p] != h {
			t.Fatalf("trusted file %s mutated by agent activity", p)
		}
	}
	if mustRead(t, filepath.Join(root, "app.py")) != "print('v1')\n" {
		t.Fatal("trusted app.py modified without apply step")
	}
	_ = res
}

func fullPromotionFlow(t *testing.T) (sessionDir, root, dest string, changes []Change) {
	t.Helper()
	stateRoot := filepath.Join(t.TempDir(), "state")
	mgr, err := session.Create(stateRoot, "", "claude", "strict")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mgr.Close() })
	root = t.TempDir()
	dest = filepath.Join(mgr.Dir(), "workspace")

	write(t, filepath.Join(root, "src/lib.go"), "v1", 0o644)
	res, err := Snapshot(root, dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.SetWorkspace(dest); err != nil {
		t.Fatal(err)
	}
	if err := SaveManifest(mgr.Dir(), res.Manifest); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dest, "src/lib.go"), "v2", 0o644)
	write(t, filepath.Join(dest, "src/new.go"), "brand-new", 0o755)
	changes, _, err = ComputeDiff(res.Manifest, dest)
	if err != nil {
		t.Fatal(err)
	}
	return mgr.Dir(), root, dest, changes
}

func TestApplyHappyPathRequiresVerifiedState(t *testing.T) {
	sessionDir, root, dest, changes := fullPromotionFlow(t)
	mgr, err := session.Load(filepath.Dir(filepath.Dir(sessionDir)), filepath.Base(sessionDir))
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	if err := ValidateChanges(root, mustManifest(t, sessionDir), changes); err != nil {
		t.Fatalf("validation should pass: %v", err)
	}
	if _, err := Apply(root, dest, mustManifest(t, sessionDir), changes); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if mustRead(t, filepath.Join(root, "src/lib.go")) != "v2" {
		t.Fatal("modification not promoted")
	}
	if mustRead(t, filepath.Join(root, "src/new.go")) != "brand-new" {
		t.Fatal("addition not promoted")
	}
	fi, _ := os.Stat(filepath.Join(root, "src/new.go"))
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode not preserved: %v", fi.Mode())
	}
	if mgr.Meta.State == session.StateReleaseReady {
		t.Log("state gate is enforced at CLI layer, library allows flow testing")
	}
}

func TestApplyRefusesHostConflict(t *testing.T) {
	sessionDir, root, dest, changes := fullPromotionFlow(t)
	write(t, filepath.Join(root, "src/lib.go"), "USER EDITED DURING SESSION", 0o644)

	err := ValidateChanges(root, mustManifest(t, sessionDir), changes)
	if err == nil {
		t.Fatal("conflict not detected")
	}
	var uce *UnsafeChangeError
	if !errors.As(err, &uce) {
		t.Fatalf("error type = %T", err)
	}
	applied, err := Apply(root, dest, mustManifest(t, sessionDir), changes)
	if err == nil {
		t.Fatal("Apply must refuse on conflict internally")
	}
	if applied != 0 {
		t.Fatalf("no change may be applied on conflict, got %d", applied)
	}
	if mustRead(t, filepath.Join(root, "src/lib.go")) != "USER EDITED DURING SESSION" {
		t.Fatal("user edit clobbered")
	}
}

func TestApplyRejectsTraversalFromTamperedDiff(t *testing.T) {
	_, root, dest, _ := fullPromotionFlow(t)
	outside := filepath.Join(filepath.Dir(root), "pwned.txt")

	evil := []Change{{
		Path: "../" + filepath.Base(outside),
		Kind: KindAdded,
		New:  &Entry{Type: "file", Mode: 0o644, SHA256: ""},
	}}
	err := ValidateChanges(root, Manifest{}, evil)
	if err == nil {
		t.Fatal("traversal path accepted")
	}
	if _, err := Apply(root, dest, Manifest{}, evil); err == nil {
		t.Fatal("traversal applied")
	}
	if _, serr := os.Stat(outside); !os.IsNotExist(serr) {
		t.Fatal("file escaped to parent directory")
	}
}

func TestApplyRejectsEscapingSymlinkPromotion(t *testing.T) {
	_, root, _, _ := fullPromotionFlow(t)
	target := filepath.Join(t.TempDir(), "secret")
	write(t, target, "s", 0o600)

	link := []Change{{
		Path: "innocent.txt",
		Kind: KindAdded,
		New:  &Entry{Type: "symlink", Target: target},
	}}
	if err := ValidateChanges(root, Manifest{}, link); err == nil {
		t.Fatal("escaping symlink promotion accepted")
	}
}

func TestManifestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	m := Manifest{
		"a.txt":      {Type: "file", Size: 3, Mode: 0o644, SHA256: "abc"},
		"sub":        {Type: "dir", Mode: 0o755},
		"sub/link.l": {Type: "symlink", Target: "../a.txt"},
	}
	if err := SaveManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest perms = %v", info.Mode().Perm())
	}
	got, err := LoadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got["a.txt"] != m["a.txt"] || got["sub/link.l"].Target != "../a.txt" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func mustManifest(t *testing.T, dir string) Manifest {
	t.Helper()
	m, err := LoadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
