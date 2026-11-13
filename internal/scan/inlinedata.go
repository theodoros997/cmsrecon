package scan

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/theodoros997/cmsrecon/internal/vulndb"
)

// confVersionScriptData is the confidence of a version read from the data
// a plugin passes to its own script.
const confVersionScriptData = 60

// versionKeys are the keys plugins use for their version in that data.
var versionKeys = []string{"version", "ver", "plugin_version", "pluginVersion", "plugin_ver"}

// pluginsFromInlineData reads the version a plugin passes to its own
// script. WordPress prints an enqueued script as <script id="HANDLE-js"
// src="…/plugins/SLUG/…"> and the data given to wp_localize_script or
// wp_add_inline_script as <script id="HANDLE-js-extra">var x = {…};
// </script>: a top-level "version" in the data of a script from the
// plugin's folder is the plugin's own (elementorFrontendConfig has one).
// It costs no request.
func (s *Scanner) pluginsFromInlineData(set *componentSet, pages []labelledPage, prefix string, core *Version) {
	for _, p := range pages {
		handles := map[string]string{} // script handle -> plugin slug
		for _, sc := range p.scripts {
			handle, ok := strings.CutSuffix(sc.id, "-js")
			if !ok || sc.src == nil {
				continue
			}
			if u, ok := s.siteURL(sc.src); ok {
				if slug := slugIn(u.Path, prefix); slug != "" {
					handles[handle] = slug
				}
			}
		}
		for _, sc := range p.scripts {
			if sc.src != nil {
				continue
			}
			handle := sc.id
			for _, suffix := range []string{"-js-extra", "-js-before", "-js-after"} {
				handle = strings.TrimSuffix(handle, suffix)
			}
			slug, ok := handles[handle]
			if !ok || handle == sc.id {
				continue
			}
			if v := dataVersion(sc.inline); v != "" && !isCoreVersion(v, core) {
				set.addVersion(slug, Evidence{Method: "Version in the data of the plugin's script", Mode: p.mode, URL: p.resp.URL.String(), Value: v, Confidence: confVersionScriptData})
			}
		}
	}
}

// dataVersion returns the top-level version of the first JSON object
// assigned in an inline script that has one: var x = {"version":"1.2.3"}.
func dataVersion(js string) string {
	for rest := js; ; {
		i := strings.Index(rest, "{")
		if i < 0 {
			return ""
		}
		// Only objects that are assigned or passed: "= {" or "({".
		before := strings.TrimRight(rest[:i], " \t\r\n")
		rest = rest[i:]
		if !strings.HasSuffix(before, "=") && !strings.HasSuffix(before, "(") {
			rest = rest[1:]
			continue
		}
		var obj map[string]json.RawMessage
		dec := json.NewDecoder(bytes.NewReader([]byte(rest)))
		if err := dec.Decode(&obj); err != nil {
			rest = rest[1:]
			continue
		}
		for _, k := range versionKeys {
			var v string
			if json.Unmarshal(obj[k], &v) == nil && vulndb.Valid(v) && strings.Contains(v, ".") {
				return vulndb.Normalize(v)
			}
		}
		rest = rest[dec.InputOffset():]
	}
}
