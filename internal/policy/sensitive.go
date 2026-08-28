package policy

import (
	"path/filepath"
	"strings"
)

func isEnvFile(name string) bool {
	return name == ".env" || strings.HasPrefix(name, ".env.")
}

func isKeyFile(name string) bool {
	switch name {
	case "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa":
		return true
	}
	return strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") ||
		strings.HasSuffix(name, ".p12") || strings.HasSuffix(name, ".pfx") ||
		strings.HasSuffix(name, ".kdbx")
}

var sensitiveExactNames = map[string]bool{
	".netrc":           true,
	".npmrc":           true,
	".pypirc":          true,
	"credentials":      true,
	".git-credentials": true,
	"authorized_keys":  true,
}

var sensitiveSubstrings = []string{
	"secret", "credential", "password", "private_key", "privatekey",
}

func IsSensitivePath(path string) bool {
	if path == "" {
		return false
	}
	name := strings.ToLower(filepath.Base(path))
	if isEnvFile(name) || isKeyFile(name) || sensitiveExactNames[name] {
		return true
	}
	dir := strings.ToLower(filepath.ToSlash(filepath.Dir(path)))
	if strings.Contains(dir, "/.ssh/") || strings.HasSuffix(dir, "/.ssh") ||
		strings.Contains(dir, "/.aws/") || strings.HasSuffix(dir, "/.aws") {
		return true
	}
	for _, s := range sensitiveSubstrings {
		if strings.Contains(name, s) {
			return true
		}
	}
	return false
}
