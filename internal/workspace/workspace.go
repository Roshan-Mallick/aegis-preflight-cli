package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var excludedDirs = map[string]bool{
	".git": true, "node_modules": true, "__pycache__": true,
	".venv": true, "venv": true, ".tox": true, ".mypy_cache": true,
	".pytest_cache": true, ".next": true, ".cache": true,
	"target": true, "dist": true, "vendor": true,
	".aegis": true, ".claude": true, ".opencode": true,
}

var (
	SnapshotMaxBytes int64 = 2 << 30
	SnapshotMaxFiles       = 200000
)

// DetectRoot resolves the launch directory itself as the security boundary.
//
// PROJECT_ROOT = canonical(realpath(start)): the exact directory the agent is
// launched from (or given via --project). There is no marker-based walk-up and
// no snapshot copy — this directory is mounted directly into the sandbox as
// /workspace and is the only writable, reachable filesystem realm for the
// agent. The user's home directory and the filesystem root are refused as
// boundaries: mounting the home directory would expose every sibling project,
// and mounting "/" would expose the whole host filesystem.
func DetectRoot(start string) (string, error) {
	abs, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("not a directory: %s", abs)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve real path: %w", err)
	}
	home, _ := os.UserHomeDir()
	if home != "" && real == home {
		return "", fmt.Errorf("refusing to use home directory as project root")
	}
	if real == string(filepath.Separator) {
		return "", fmt.Errorf("refusing to use filesystem root as project root")
	}
	return real, nil
}

// WithinRoot reports whether candidate lives inside — or is exactly — the
// project boundary root. It compares component-wise (never by naive string
// prefix) and, when the candidate exists on disk, resolves symlinks first so
// an escape aimed through a link is never reported as "inside". This mirrors,
// for host-side paths, the container mount boundary that makes /workspace the
// only reachable writable realm.
func WithinRoot(root, candidate string) (bool, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	candAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false, err
	}
	if ev, err := filepath.EvalSymlinks(candAbs); err == nil {
		candAbs = ev
	}
	rel, err := filepath.Rel(rootAbs, candAbs)
	if err != nil {
		return false, err
	}
	return validRel(rel), nil
}

type Entry struct {
	Type   string `json:"type"`
	Size   int64  `json:"size,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Target string `json:"target,omitempty"`
}

type Manifest map[string]Entry

type SnapshotResult struct {
	FilesCopied     int
	DirsCreated     int
	BytesCopied     int64
	SkippedSymlinks []string
	Manifest        Manifest
}

func shouldExclude(rel string) bool {
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if excludedDirs[part] {
			return true
		}
	}
	return false
}

func validRel(p string) bool {
	if p == "" || filepath.IsAbs(p) {
		return false
	}
	clean := filepath.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func symlinkEscapes(baseDir, linkPath, target string) bool {
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(linkPath), target)
	}
	final, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return true
	}
	rel, err := filepath.Rel(baseDir, final)
	if err != nil {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	return false
}

func Snapshot(root, dest string) (*SnapshotResult, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(rootAbs)
	if err != nil {
		return nil, fmt.Errorf("project root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("project root is not a directory: %s", rootAbs)
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}

	res := &SnapshotResult{Manifest: Manifest{}}
	err = filepath.WalkDir(rootAbs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(rootAbs, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if !validRel(rel) {
			return fmt.Errorf("unexpected path during snapshot: %s", rel)
		}
		if d.IsDir() {
			if shouldExclude(rel) {
				return filepath.SkipDir
			}
			fi, err := d.Info()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Join(dest, rel), fi.Mode().Perm()); err != nil {
				return err
			}
			res.DirsCreated++
			res.Manifest[rel] = Entry{Type: "dir", Mode: uint32(fi.Mode().Perm())}
			return nil
		}
		if shouldExclude(rel) {
			return nil
		}
		if res.FilesCopied+1 > SnapshotMaxFiles {
			return fmt.Errorf("snapshot aborted: file count exceeds limit (%d)", SnapshotMaxFiles)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if symlinkEscapes(rootAbs, path, target) {
				res.SkippedSymlinks = append(res.SkippedSymlinks, rel)
				return nil
			}
			if err := os.Symlink(target, filepath.Join(dest, rel)); err != nil {
				return err
			}
			fi, err := d.Info()
			if err != nil {
				return err
			}
			res.Manifest[rel] = Entry{Type: "symlink", Target: target, Mode: uint32(fi.Mode().Perm())}
			return nil
		}
		if !d.Type().IsRegular() {
			res.SkippedSymlinks = append(res.SkippedSymlinks, rel)
			return nil
		}
		sum, size, err := hashFile(path)
		if err != nil {
			return err
		}
		res.BytesCopied += size
		if res.BytesCopied > SnapshotMaxBytes {
			return fmt.Errorf("snapshot aborted: total size exceeds limit (%d bytes)", SnapshotMaxBytes)
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			src.Close()
			return err
		}
		dstPath := filepath.Join(dest, rel)
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o700); err != nil {
			src.Close()
			return err
		}
		dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode().Perm())
		if err != nil {
			src.Close()
			return err
		}
		if _, err := io.Copy(dst, src); err != nil {
			src.Close()
			dst.Close()
			return err
		}
		src.Close()
		dst.Close()
		res.FilesCopied++
		res.Manifest[rel] = Entry{Type: "file", Size: size, Mode: uint32(fi.Mode().Perm()), SHA256: sum}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("snapshot %s: %w", rootAbs, err)
	}
	return res, nil
}

type ChangeKind string

const (
	KindAdded      ChangeKind = "added"
	KindModified   ChangeKind = "modified"
	KindDeleted    ChangeKind = "deleted"
	KindTypeChange ChangeKind = "type_changed"
)

type Change struct {
	Path string     `json:"path"`
	Kind ChangeKind `json:"kind"`
	Old  *Entry     `json:"old,omitempty"`
	New  *Entry     `json:"new,omitempty"`
}

func buildCurrentManifest(base string) (Manifest, error) {
	m := Manifest{}
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return nil, err
	}
	err = filepath.WalkDir(baseAbs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(baseAbs, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if shouldExclude(rel) {
				return filepath.SkipDir
			}
			fi, err := d.Info()
			if err != nil {
				return err
			}
			m[rel] = Entry{Type: "dir", Mode: uint32(fi.Mode().Perm())}
			return nil
		}
		if shouldExclude(rel) {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			fi, err := d.Info()
			if err != nil {
				return err
			}
			m[rel] = Entry{Type: "symlink", Target: target, Mode: uint32(fi.Mode().Perm())}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		sum, size, err := hashFile(path)
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		m[rel] = Entry{Type: "file", Size: size, Mode: uint32(fi.Mode().Perm()), SHA256: sum}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// BuildManifest computes the current manifest of a live directory. In the
// direct-mount model this is the project root itself: the audit baseline for
// the session is the project as it exists, and never a copy.
func BuildManifest(base string) (Manifest, error) {
	return buildCurrentManifest(base)
}

func ComputeDiff(before Manifest, workspace string) ([]Change, Manifest, error) {
	current, err := buildCurrentManifest(workspace)
	if err != nil {
		return nil, nil, fmt.Errorf("scan workspace: %w", err)
	}
	var changes []Change
	paths := map[string]bool{}
	for p := range before {
		paths[p] = true
	}
	for p := range current {
		paths[p] = true
	}
	sorted := make([]string, 0, len(paths))
	for p := range paths {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	for _, p := range sorted {
		oldE, hadOld := before[p]
		newE, hasNew := current[p]
		switch {
		case hadOld && hasNew:
			if oldE.Type != newE.Type {
				o, n := oldE, newE
				changes = append(changes, Change{Path: p, Kind: KindTypeChange, Old: &o, New: &n})
			} else if oldE.SHA256 != newE.SHA256 || oldE.Target != newE.Target ||
				(oldE.Type == "file" && oldE.Mode != newE.Mode && modeBitsDiffer(oldE.Mode, newE.Mode)) {
				o, n := oldE, newE
				changes = append(changes, Change{Path: p, Kind: KindModified, Old: &o, New: &n})
			}
		case hadOld:
			o := oldE
			changes = append(changes, Change{Path: p, Kind: KindDeleted, Old: &o})
		default:
			n := newE
			changes = append(changes, Change{Path: p, Kind: KindAdded, New: &n})
		}
	}
	return changes, current, nil
}

func modeBitsDiffer(a, b uint32) bool {
	exec := func(m uint32) uint32 { return m & 0o111 }
	return exec(a) != exec(b)
}

func SaveManifest(sessionDir string, m Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(sessionDir, "manifest.json")
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func LoadManifest(sessionDir string) (Manifest, error) {
	b, err := os.ReadFile(filepath.Join(sessionDir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("load manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return m, nil
}

type UnsafeChangeError struct {
	Violations []string
}

func (e *UnsafeChangeError) Error() string {
	return "unsafe changes rejected: " + strings.Join(e.Violations, "; ")
}

type ConflictError struct {
	Paths []string
}

func (e *ConflictError) Error() string {
	return "trusted files changed since snapshot; refusing to overwrite: " + strings.Join(e.Paths, "; ")
}

func hostMatchesSnapshot(trustedAbs, relPath string, old *Entry) (bool, string) {
	hostPath := filepath.Join(trustedAbs, relPath)
	if old != nil && old.Type == "symlink" {
		t, err := os.Readlink(hostPath)
		if err != nil {
			return false, ""
		}
		return t == old.Target, t
	}
	sum, _, err := hashFile(hostPath)
	if err != nil {
		return false, ""
	}
	if old != nil && old.Type == "file" && old.SHA256 != "" {
		return sum == old.SHA256, sum
	}
	return true, sum
}

func ValidateChanges(trustedRoot string, before Manifest, changes []Change) error {
	trustedAbs, err := filepath.Abs(trustedRoot)
	if err != nil {
		return err
	}
	var unsafe []string
	var conflicts []string
	for _, ch := range changes {
		if !validRel(ch.Path) {
			unsafe = append(unsafe, ch.Path+": illegal path")
			continue
		}
		switch ch.Kind {
		case KindAdded, KindModified, KindTypeChange:
			if ch.New == nil {
				unsafe = append(unsafe, ch.Path+": missing target entry")
				continue
			}
			if ch.New.Type == "symlink" && symlinkEscapes(trustedAbs, filepath.Join(trustedAbs, ch.Path), ch.New.Target) {
				unsafe = append(unsafe, ch.Path+": symlink escapes trusted project")
				continue
			}
			hostPath := filepath.Join(trustedAbs, ch.Path)
			_, herr := os.Lstat(hostPath)
			switch {
			case herr == nil:
				old := ch.Old
				if ch.Kind == KindAdded {
					conflicts = append(conflicts, ch.Path+": already exists on host")
					continue
				}
				if old == nil {
					conflicts = append(conflicts, ch.Path+": no snapshot baseline")
					continue
				}
				if fi, err := os.Lstat(hostPath); err == nil && fi.IsDir() && old.Type != "dir" {
					unsafe = append(unsafe, ch.Path+": would replace directory")
					continue
				}
				if ok, _ := hostMatchesSnapshot(trustedAbs, ch.Path, old); !ok {
					conflicts = append(conflicts, ch.Path+": changed on host since snapshot")
				}
			case os.IsNotExist(herr):
				if ch.Kind != KindAdded {
					conflicts = append(conflicts, ch.Path+": missing on host but present in snapshot")
				}
			default:
				conflicts = append(conflicts, ch.Path+": unreadable on host")
			}
		case KindDeleted:
			hostPath := filepath.Join(trustedAbs, ch.Path)
			if _, err := os.Lstat(hostPath); err != nil {
				if os.IsNotExist(err) {
					continue
				}
				conflicts = append(conflicts, ch.Path+": unreadable on host")
				continue
			}
			if ok, _ := hostMatchesSnapshot(trustedAbs, ch.Path, ch.Old); !ok {
				conflicts = append(conflicts, ch.Path+": changed on host since snapshot")
			}
		default:
			unsafe = append(unsafe, ch.Path+": unknown change kind")
		}
	}
	if len(unsafe) > 0 || len(conflicts) > 0 {
		return &UnsafeChangeError{Violations: append(unsafe, conflicts...)}
	}
	return nil
}

// ValidatePromotion is the direct-mount equivalent of ValidateChanges. In the
// in-place sandbox the workspace IS the trusted project: agent edits land
// directly in the project and that is the contract, so there is no separate
// baseline conflict to guard against. Security validation still applies in
// full: every change must be a legal relative path and no symlink target may
// escape the project when followed from the host side.
func ValidatePromotion(trustedRoot string, before Manifest, changes []Change) error {
	trustedAbs, err := filepath.Abs(trustedRoot)
	if err != nil {
		return err
	}
	var unsafe []string
	for _, ch := range changes {
		if !validRel(ch.Path) {
			unsafe = append(unsafe, ch.Path+": illegal path")
			continue
		}
		switch ch.Kind {
		case KindAdded, KindModified, KindTypeChange:
			if ch.New == nil {
				unsafe = append(unsafe, ch.Path+": missing target entry")
				continue
			}
			if ch.New.Type == "symlink" && symlinkEscapes(trustedAbs, filepath.Join(trustedAbs, ch.Path), ch.New.Target) {
				unsafe = append(unsafe, ch.Path+": symlink escapes trusted project")
			}
		case KindDeleted:
			// A deletion is symmetric here: the file is (or just was) part
			// of the project.
		default:
			unsafe = append(unsafe, ch.Path+": unknown change kind")
		}
	}
	if len(unsafe) > 0 {
		return &UnsafeChangeError{Violations: unsafe}
	}
	return nil
}

// Apply promotes verified changes from a separate workspace copy into the
// trusted root. With the direct-mount model this path is retained only as a
// bounded utility for explicit copy-based flows (e.g. the e2e harness); the
// live pipeline no longer produces a workspace copy to promote.
func Apply(trustedRoot, workspace string, before Manifest, changes []Change) (int, error) {
	if err := ValidateChanges(trustedRoot, before, changes); err != nil {
		return 0, err
	}
	trustedAbs, err := filepath.Abs(trustedRoot)
	if err != nil {
		return 0, err
	}
	wsAbs, err := filepath.Abs(workspace)
	if err != nil {
		return 0, err
	}
	applied := 0
	for _, ch := range changes {
		if !validRel(ch.Path) || ch.New == nil {
			return applied, &UnsafeChangeError{Violations: []string{ch.Path + ": invalid change"}}
		}
		hostPath := filepath.Join(trustedAbs, ch.Path)
		wsPath := filepath.Join(wsAbs, ch.Path)
		if ch.Kind == KindDeleted {
			if err := os.Remove(hostPath); err != nil && !os.IsNotExist(err) {
				return applied, fmt.Errorf("delete %s: %w", ch.Path, err)
			}
			applied++
			continue
		}
		if err := os.MkdirAll(filepath.Dir(hostPath), 0o700); err != nil {
			return applied, fmt.Errorf("prepare parent of %s: %w", ch.Path, err)
		}
		switch ch.New.Type {
		case "dir":
			if err := os.MkdirAll(hostPath, fs.FileMode(ch.New.Mode)); err != nil {
				return applied, fmt.Errorf("mkdir %s: %w", ch.Path, err)
			}
			applied++
		case "symlink":
			if symlinkEscapes(trustedAbs, hostPath, ch.New.Target) {
				return applied, &UnsafeChangeError{Violations: []string{ch.Path + ": symlink escapes trusted project"}}
			}
			os.Remove(hostPath)
			if err := os.Symlink(ch.New.Target, hostPath); err != nil {
				return applied, fmt.Errorf("symlink %s: %w", ch.Path, err)
			}
			applied++
		case "file":
			src, err := os.Open(wsPath)
			if err != nil {
				return applied, fmt.Errorf("open workspace copy of %s: %w", ch.Path, err)
			}
			sum, _, err := hashFile(wsPath)
			src.Close()
			if err != nil {
				return applied, fmt.Errorf("hash workspace copy of %s: %w", ch.Path, err)
			}
			if ch.New.SHA256 != "" && sum != ch.New.SHA256 {
				return applied, fmt.Errorf("workspace copy of %s drifted from verified diff", ch.Path)
			}
			os.Remove(hostPath)
			dst, err := os.OpenFile(hostPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fs.FileMode(ch.New.Mode)&0o777)
			if err != nil {
				return applied, fmt.Errorf("write %s: %w", ch.Path, err)
			}
			src2, err := os.Open(wsPath)
			if err != nil {
				dst.Close()
				return applied, fmt.Errorf("reopen workspace copy of %s: %w", ch.Path, err)
			}
			_, cerr := io.Copy(dst, src2)
			src2.Close()
			derr := dst.Close()
			if cerr != nil {
				return applied, fmt.Errorf("copy %s: %w", ch.Path, cerr)
			}
			if derr != nil {
				return applied, fmt.Errorf("finalize %s: %w", ch.Path, derr)
			}
			os.Chmod(hostPath, fs.FileMode(ch.New.Mode)&0o777)
			applied++
		default:
			return applied, &UnsafeChangeError{Violations: []string{ch.Path + ": unknown entry type"}}
		}
	}
	return applied, nil
}

func TreeDigest(root string) (map[string]string, error) {
	m, err := buildCurrentManifest(root)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(m))
	for p, e := range m {
		blob, _ := json.Marshal(e)
		sum := sha256.Sum256(blob)
		out[p] = hex.EncodeToString(sum[:])
	}
	return out, nil
}
