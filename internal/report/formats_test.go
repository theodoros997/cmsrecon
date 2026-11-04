package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/theodoros997/cmsrecon/internal/scan"
)

// hostile puts markup in every place a target controls.
func hostile() *scan.Result {
	r := sampleResult()
	r.Plugins[0].Name = `<script>alert(1)</script>`
	r.Plugins[0].Vulnerabilities[0].Title = `Bad | [link](https://evil.example/) ![img](x) <img src=x onerror=alert(1)>`
	r.MainTheme.Name = "*bold* _it_ `code` # heading\nnew line"
	r.Users[0].DisplayName = `<b>admin</b> | x`
	r.InterestingFindings[0].Entries = []string{`<iframe src="https://evil.example/">`}
	r.Summary = scan.Summarize(r)
	return r
}

func TestHTMLReport(t *testing.T) {
	var b bytes.Buffer
	if err := WriteHTML(&b, sampleResult()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"<!DOCTYPE html>", "<title>WordPress scan: https://example.com/</title>",
		"Summary", "plugin contact-form-7 5.3.1: Contact Form 7 &lt;= 5.3.1 - Unrestricted File Upload", "public exploit",
		"Debug log exposed", "CVE-2020-35489", "CVSS 9.8", "fixed in 5.3.2", "1 Metasploit module",
		"child", "main theme", "parent theme", "Possible vulnerabilities: 3 (1 critical)",
		"Guest Writer", "salaries.xlsx", "Wordfence (2026-10-19)", "2 confirmed, 4 possible",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
	if strings.Contains(out, "<script") || strings.Contains(out, "src=") || strings.Contains(out, "<link") {
		t.Error("the HTML report must be self-contained: no script, no external file")
	}

	b.Reset()
	if err := WriteHTML(&b, hostile()); err != nil {
		t.Fatal(err)
	}
	out = b.String()
	for _, bad := range []string{"<script>alert", "<img src=x", "<iframe", "<b>admin</b>"} {
		if strings.Contains(out, bad) {
			t.Errorf("HTML report lets %q through", bad)
		}
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("the plugin name should be shown, escaped")
	}
}

func TestMarkdownReport(t *testing.T) {
	var b bytes.Buffer
	if err := WriteMarkdown(&b, sampleResult()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# WordPress scan report", "## Summary", "| **CRITICAL** | plugin contact-form-7 5.3.1: Contact Form 7 \\<= 5.3.1 - Unrestricted File Upload | confirmed · CVE-2020-35489 · **public exploit** |",
		"| **HIGH** | Debug log exposed | <https://example.com/wp-content/debug.log> |",
		"### contact-form-7 (Contact Form 7)", "- Location: <https://example.com/wp-content/plugins/contact-form-7/>",
		"<https://www.exploit-db.com/exploits/49294>", "| 1 | admin | Site Admin | 100% |", "## Scan",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Markdown report missing %q", want)
		}
	}
	if strings.Contains(out, "\n\n\n") {
		t.Error("the Markdown report has runs of blank lines")
	}

	b.Reset()
	if err := WriteMarkdown(&b, hostile()); err != nil {
		t.Fatal(err)
	}
	out = b.String()
	// Drop what is escaped; markup must not remain.
	bare := strings.NewReplacer(`\<`, "", `\|`, "", `\[`, "", `\!`, "", "\\`", "", `\*`, "").Replace(out)
	for _, bad := range []string{"<script>", "[link](", "![img]", "<img", "<iframe", "<b>admin", "| x |", "*bold*", "`code`", "\nnew line"} {
		if strings.Contains(bare, bad) {
			t.Errorf("Markdown report lets %q through", bad)
		}
	}
	for _, want := range []string{`\<script\>alert(1)\</script\>`, `Bad \| \[link\](https://evil.example/)`, `\<b\>admin\</b\> \| x`} {
		if !strings.Contains(out, want) {
			t.Errorf("Markdown report missing the escaped %q", want)
		}
	}
	// Every table row keeps its columns.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| **CRITICAL** | Bad") {
			if n := strings.Count(strings.ReplaceAll(line, `\|`, ""), "|"); n != 4 {
				t.Errorf("table row has %d separators: %s", n, line)
			}
		}
	}
}

func TestMarkdownURLs(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.com/a_b/":       "<https://example.com/a_b/>",
		"https://example.com/a>b":        `https://example.com/a\>b`,
		"https://example.com/a|b":        `https://example.com/a\|b`,
		"javascript:alert(1)":            "javascript:alert(1)",
		"https://example.com/x y":        "https://example.com/x y",
		"https://example.com/[a](b)":     "<https://example.com/[a](b)>",
		"ftp://example.com/file":         "ftp://example.com/file",
		"https://example.com/a\nb":       "https://example.com/a b",
		"http://example.com/?q=<script>": `http://example.com/?q=\<script\>`,
	} {
		if got := mdURL(in); got != want {
			t.Errorf("mdURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSummaryNotChecked(t *testing.T) {
	r := sampleResult()
	r.VulnerabilityData = &scan.DataInfo{}
	for _, p := range r.Plugins {
		p.Vulnerabilities = nil
	}
	r.JSLibraries[0].Vulnerabilities = nil
	r.Timthumbs[0].Vulnerabilities = nil
	r.InterestingFindings = r.InterestingFindings[:1] // only the low one
	r.VulnerabilityCounts = scan.VulnCounts{}
	r.Summary = scan.Summarize(r)

	var b bytes.Buffer
	if err := WriteCLI(&b, r, Options{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "Not checked: there is no vulnerability data") || strings.Contains(out, "None matched") {
		t.Errorf("without data the report must say vulnerabilities were not checked:\n%s", out)
	}
	if !strings.Contains(out, "vulnerabilities were not checked (no vulnerability data)") {
		t.Errorf("summary without data:\n%s", out)
	}
}

func TestBrief(t *testing.T) {
	var b bytes.Buffer
	if err := WriteBrief(&b, sampleResult(), Options{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Found: WordPress 6.4.2, 1 plugin, 3 themes, 1 JavaScript library, 2 users, 2 interesting findings",
		"Vulnerabilities: 2 confirmed, 4 possible", "Summary", "CRITICAL plugin contact-form-7 5.3.1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("brief missing %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "\n"); n > 12 {
		t.Errorf("the brief should stay short, got %d lines", n)
	}
}

func TestReadJSON(t *testing.T) {
	var b bytes.Buffer
	in := sampleResult()
	if err := WriteJSON(&b, in); err != nil {
		t.Fatal(err)
	}
	r, err := ReadJSON(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if r.Plugins[0].Slug != "contact-form-7" || r.MainTheme.Parent.Slug != "parent" || len(r.Summary.Risks) != len(in.Summary.Risks) {
		t.Errorf("round trip lost data: %+v", r)
	}

	// An older report without a summary gets one.
	data := strings.Replace(b.String(), `"summary"`, `"old_summary"`, 1)
	if r, err = ReadJSON([]byte(data)); err != nil || r.Summary == nil || len(r.Summary.Risks) == 0 {
		t.Errorf("report without summary = %v, %v", r, err)
	}

	for _, bad := range []string{`{}`, `not json`, `{"schema_version": 1, "tool": {"name": "wpscan"}}`, `{"schema_version": 99, "tool": {"name": "cmsrecon"}}`} {
		if _, err := ReadJSON([]byte(bad)); err == nil {
			t.Errorf("ReadJSON(%s): want an error", bad)
		}
	}
}
