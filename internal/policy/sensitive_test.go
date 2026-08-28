package policy

import "testing"

func TestIsSensitivePath(t *testing.T) {
	sensitive := []string{
		".env", ".env.local", "/w/app/.env.production",
		"/home/u/.ssh/id_rsa", "keys/id_ed25519",
		"certs/server.pem", "tls/private.key", "backup.p12",
		"config/credentials.yml", "secrets.json", "my-secret.txt",
		"/w/db/password.txt", "Private_KEY.pem",
		".npmrc", ".netrc", ".git-credentials",
	}
	for _, p := range sensitive {
		if !IsSensitivePath(p) {
			t.Errorf("%q should be sensitive", p)
		}
	}
	benign := []string{
		"main.go", "src/app.py", "README.md", "package.json",
		"keynote.txt", "monkey.py", "envelope.txt",
	}
	for _, p := range benign {
		if IsSensitivePath(p) {
			t.Errorf("%q should NOT be sensitive", p)
		}
	}
}
