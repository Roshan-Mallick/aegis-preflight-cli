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

// TestDetectRootUsesLaunchDir pins the new boundary semantics: PROJECT_ROOT
// is the launch directory itself, canonicalized to its real path. There is no
// marker-based walk-up, so a nested launch dir stays the root even when a
// parent contains a go.mod.
func TestDetectRootUsesLaunchDir(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "go.mod"), "module x\n", 0o644)
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := DetectRoot(nested)
	if err != nil {
		t.Fatalf("DetectRoot: %v", err)
	}
	if got != nested {
		t.Fatalf("root = %s, want the launch dir itself %s", got, nested)
	}

	// Launching on the marker owner itself also keeps that exact directory.
	got, err = DetectRoot(root)
	if err != nil {
		t.Fatalf("DetectRoot: %v", err)
	}
	if got != root {
		t.Fatalf("root = %s, want %s", got, root)
	}
}

// TestDetectRootCanonicalizesSymlinks confirms the boundary is resolved to
// its real path: a project reached through a symlink is still anchored at
// the physical directory that gets bind-mounted.
func TestDetectRootCanonicalizesSymlinks(t *testing.T) {
	real := t.TempDir()
	write(t, filepath.Join(real, "app.txt"), "x", 0o644)
	link, err := os.MkdirTemp(t.TempDir(), "link")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(link)
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	got, err := DetectRoot(link)
	if err != nil {
		t.Fatalf("DetectRoot: %v", err)
	}
	if got != real {
		t.Fatalf("root = %s, want canonical real path %s", got, real)
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

func TestDetectRootRefusesHomeAndFilesystemRoot(t *testing.T) {
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		if _, err := DetectRoot(home); err == nil {
			t.Fatal("home directory must not be accepted as project root")
		}
	}
	if _, err := DetectRoot(string(filepath.Separator)); err == nil {
		t.Fatal("filesystem root must not be accepted as project root")
	}
}

// TestWithinBoundary exercises the component-wise boundary test used for
// host-side path safety: the boundary itself and everything beneath it are
// inside; parents, siblings, and visual-prefix lookalikes are outside.
func TestWithinBoundary(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(root)

	tests := []struct {
		name      string
		candidate string
		want      bool
	}{
		{"boundary itself", root, true},
		{"direct child", src, true},
		{"nonexistent descendant", filepath.Join(src, "nope"), true},
		{"sibling", root + "2", false},
		{"parent", parent, false},
		{"grandparent", filepath.Dir(parent), false},
	}
	for _, tc := range tests {
		if got, err := WithinRoot(root, tc.candidate); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		} else if got != tc.want {
			t.Errorf("%s: within(%q) = %v, want %v", tc.name, tc.candidate, got, tc.want)
		}
	}
}

// TestWithinBoundaryDetectsSymlinkEscapes: a candidate path that crosses the
// boundary through a symlink is reported outside, mirroring the container
// mount boundary where an interior link cannot reach host paths.
func TestWithinBoundaryDetectsSymlinkEscapes(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	write(t, secret, "s", 0o600)
	if err := os.Symlink(outside, filepath.Join(root, "backdoor")); err != nil {
		t.Fatal(err)
	}
	if got, err := WithinRoot(root, filepath.Join(root, "backdoor", "secret")); err != nil {
		t.Fatal(err)
	} else if got {
		t.Fatal("candidate escaping through a symlink reported inside the boundary")
	}
	if got, err := WithinRoot(root, filepath.Join(root, "backdoor")); err != nil {
		t.Fatal(err)
	} else if got {
		t.Fatal("the link entry itself resolves to the outside dir and must be outside")
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

// TestDirectWorkspaceBaselineAndDiff pins the direct-mount contract: the
// audit baseline is a manifest of the live project (BuildManifest, never a
// copy), the agent edits the SAME project directory in place, and ComputeDiff
// resolves that into the session change set. Excluded dirs (.aegis hooks,
// .git, package caches) never enter the diff.
func TestDirectWorkspaceBaselineAndDiff(t *testing.T) {
	project := t.TempDir()
	write(t, filepath.Join(project, "app.py"), "print('v1')\n", 0o644)
	write(t, filepath.Join(project, ".env"), "SECRET=host-only\n", 0o600)

	before, err := BuildManifest(project)
	if err != nil {
		t.Fatal(err)
	}

	// "Agent" edits land directly in the project directory.
	write(t, filepath.Join(project, "app.py"), "print('v2')\n", 0o644)
	write(t, filepath.Join(project, "feature.py"), "print('new')\n", 0o644)
	write(t, filepath.Join(project, ".aegis", "bin", "hook.sh"), "# hook", 0o700)
	write(t, filepath.Join(project, "node_modules", "x.js"), "cache", 0o644)
	os.Remove(filepath.Join(project, ".env"))

	changes, current, err := ComputeDiff(before, project)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Change{}
	for _, ch := range changes {
		got[ch.Path] = ch
	}
	if got["app.py"].Kind != KindModified {
		t.Errorf("app.py = %s, want modified", got["app.py"].Kind)
	}
	if got["feature.py"].Kind != KindAdded {
		t.Errorf("feature.py = %s, want added", got["feature.py"].Kind)
	}
	if got[".env"].Kind != KindDeleted {
		t.Errorf(".env = %s, want deleted", got[".env"].Kind)
	}
	for _, p := range []string{".aegis/bin/hook.sh", "node_modules/x.js"} {
		if _, ok := got[p]; ok {
			t.Errorf("excluded path %s must not enter the diff", p)
		}
	}
	// The in-place contract: edits are already in the live project.
	if mustRead(t, filepath.Join(project, "app.py")) != "print('v2')\n" {
		t.Fatal("agent edit missing from live project")
	}
	if _, ok := current["app.py"]; !ok {
		t.Fatal("current manifest missing the edited file")
	}
}

// TestValidatePromotionAllowsInPlaceChanges: in the direct model the "host"
// and the "workspace" are the same directory, so promotion validation must
// accept the agent's in-place edits while still refusing illegal paths and
// symlinks that escape the project when followed from the host side.
func TestValidatePromotionAllowsInPlaceChanges(t *testing.T) {
	project := t.TempDir()
	write(t, filepath.Join(project, "src/lib.go"), "v1", 0o644)
	before, err := BuildManifest(project)
	if err != nil {
		t.Fatal(err)
	}

	write(t, filepath.Join(project, "src/lib.go"), "v2", 0o644)
	write(t, filepath.Join(project, "src/new.go"), "brand-new", 0o755)
	os.Remove(filepath.Join(project, "src/nonexistent.go"))
	changes, _, err := ComputeDiff(before, project)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) == 0 {
		t.Fatal("expected in-place changes")
	}
	if err := ValidatePromotion(project, before, changes); err != nil {
		t.Fatalf("in-place changes must validate: %v", err)
	}

	// An escaping symlink added by the agent is refused at promotion time.
	outside := filepath.Join(t.TempDir(), "pwned.txt")
	write(t, outside, "s", 0o600)
	link := []Change{{
		Path: "innocent.txt",
		Kind: KindAdded,
		New:  &Entry{Type: "symlink", Target: outside},
	}}
	err = ValidatePromotion(project, before, link)
	var uce *UnsafeChangeError
	if !errors.As(err, &uce) {
		t.Fatalf("escaping symlink not refused: %T %v", err, err)
	}
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
