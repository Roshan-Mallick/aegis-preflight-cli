package findings

import "testing"

func FuzzParseGitleaks(f *testing.F) {
	f.Add([]byte(`[{"Description":"test","StartLine":1,"File":"x.py","RuleID":"generic-api-key","Severity":"HIGH","Secret":"x","Fingerprint":"y"}]`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))
	f.Add([]byte(`[{"Description":"","StartLine":0,"File":"","RuleID":"","Severity":"","Secret":"","Fingerprint":""}]`))
	f.Add([]byte(`[{"Description":"a","StartLine":1,"File":"b","RuleID":"c","Severity":"critical","Secret":"d","Fingerprint":"e"},{"Description":"f","StartLine":2,"File":"g","RuleID":"h","Severity":"low","Secret":"i","Fingerprint":"j"}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		fs := ParseGitleaks(data)
		for _, finding := range fs {
			if finding.Scanner != "gitleaks" {
				t.Errorf("scanner=%s, want gitleaks", finding.Scanner)
			}
			if finding.Severity == "" {
				t.Error("empty severity")
			}
			if finding.FindingID == "" {
				t.Error("empty finding ID")
			}
		}
	})
}

func FuzzParseNpmAudit(f *testing.F) {
	f.Add([]byte(`{"vulnerabilities":{"lodash":{"name":"lodash","severity":"critical","via":["CVE-2021-23337"]}}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))
	f.Add([]byte(`{"vulnerabilities":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		fs := ParseNpmAudit(data)
		for _, finding := range fs {
			if finding.Scanner != "npm-audit" {
				t.Errorf("scanner=%s, want npm-audit", finding.Scanner)
			}
			if finding.Severity == "" {
				t.Error("empty severity")
			}
		}
	})
}

func FuzzParsePipAudit(f *testing.F) {
	f.Add([]byte(`{"dependencies":[{"name":"flask","version":"2.0.0","vulns":[{"id":"PYSEC-2023-001","description":"test","fix_versions":["2.2.5"]}]}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))
	f.Add([]byte(`{"dependencies":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		fs := ParsePipAudit(data)
		for _, finding := range fs {
			if finding.Scanner != "pip-audit" {
				t.Errorf("scanner=%s, want pip-audit", finding.Scanner)
			}
			if finding.Severity == "" {
				t.Error("empty severity")
			}
		}
	})
}
