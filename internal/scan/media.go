package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// maxMedia caps how many media the REST API is paged through for.
const maxMedia = 1000

// enumerateMedia lists uploaded files (-e m). The REST API lists them a
// hundred at a time, so it comes first; only when it is closed are the
// attachment IDs of the range requested one by one, as WPScan does.
func (s *Scanner) enumerateMedia(ctx context.Context) []*Media {
	ids := s.opts.Enumerate.Media
	if ids == nil || !s.aggressive() {
		return nil
	}
	media := s.mediaFromREST(ctx)
	if len(media) == 0 {
		media = s.mediaFromIDs(ctx, ids.From, ids.To)
	}
	slices.SortFunc(media, func(a, b *Media) int { return a.ID - b.ID })
	return media
}

func (s *Scanner) mediaFromREST(ctx context.Context) []*Media {
	const fields = "_fields=id,source_url,mime_type,title,link"
	var route func(page int) string
	if api := s.rest(ctx); api != nil {
		route = func(page int) string {
			return api.route("wp/v2/media", fmt.Sprintf("per_page=100&page=%d&%s", page, fields))
		}
	} else {
		route = func(page int) string {
			return s.urlWithQuery("wp-json/wp/v2/media", fmt.Sprintf("per_page=100&page=%d&%s", page, fields))
		}
	}
	var out []*Media
	seen := map[int]bool{}
	for page := 1; len(out) < maxMedia; page++ {
		u := route(page)
		res := s.get(ctx, u)
		if res == nil || res.StatusCode != http.StatusOK {
			break
		}
		var items []struct {
			ID    int    `json:"id"`
			URL   string `json:"source_url"`
			Mime  string `json:"mime_type"`
			Link  string `json:"link"`
			Title struct {
				Rendered string `json:"rendered"`
			} `json:"title"`
		}
		if json.Unmarshal(res.Body, &items) != nil || len(items) == 0 {
			break
		}
		for _, it := range items {
			if it.ID <= 0 || seen[it.ID] || len(out) >= maxMedia {
				continue
			}
			seen[it.ID] = true
			file, page := httpURL(it.URL), httpURL(it.Link)
			if file == "" && page == "" {
				continue
			}
			out = append(out, &Media{
				ID: it.ID, URL: file, PageURL: page, MimeType: it.Mime,
				Title:    strings.TrimSpace(html.UnescapeString(it.Title.Rendered)),
				Evidence: []Evidence{{Method: "REST API", Mode: modeAggressive, URL: u, Value: strconv.Itoa(it.ID), Confidence: 100}},
			})
		}
		total, _ := strconv.Atoi(res.Header.Get("X-WP-TotalPages"))
		if page >= total {
			break
		}
	}
	return out
}

var attachmentClassRe = regexp.MustCompile(`<body[^>]+class=["'][^"']*\battachmentid-(\d+)\b`)

// mediaFromIDs requests /?attachment_id=N. WordPress redirects it to the
// attachment page, or to the file itself when attachment pages are off
// (the default since WordPress 6.4), or serves the attachment page with an
// attachmentid-N body class.
func (s *Scanner) mediaFromIDs(ctx context.Context, from, to int) []*Media {
	ids := make([]int, 0, to-from+1)
	for id := from; id <= to; id++ {
		ids = append(ids, id)
	}
	uploads := s.content.Path + "uploads/"
	found := make([]*Media, len(ids))
	s.parallel(ctx, len(ids), func(i int) {
		id := ids[i]
		u := s.urlWithQuery("", "attachment_id="+strconv.Itoa(id))
		res := s.get(ctx, u)
		if res == nil {
			return
		}
		ev := []Evidence{{Method: "Attachment ID", Mode: modeAggressive, URL: u, Confidence: 100}}
		switch {
		case res.IsRedirect():
			loc, err := res.Location()
			if err != nil || loc.String() == s.base.String() {
				return
			}
			ev[0].Value = loc.String()
			m := &Media{ID: id, Evidence: ev}
			if strings.Contains(loc.Path, uploads) || strings.Contains(loc.Path, "/uploads/") {
				m.URL = loc.String()
			} else {
				m.PageURL = loc.String()
			}
			found[i] = m
		case res.StatusCode == http.StatusOK:
			cm := attachmentClassRe.FindSubmatch(res.Body)
			if cm == nil || string(cm[1]) != strconv.Itoa(id) {
				return
			}
			m := &Media{ID: id, PageURL: u, Evidence: ev}
			if f := s.uploadURL(res.Body, uploads); f != "" {
				m.URL, ev[0].Value = f, f
			}
			found[i] = m
		}
	})
	var out []*Media
	for _, m := range found {
		if m != nil {
			out = append(out, m)
		}
	}
	return out
}

var srcHrefRe = regexp.MustCompile(`(?i)(?:src|href)=["']([^"']+)["']`)

// uploadURL returns the first in-scope link to the uploads folder in an
// attachment page: the file it shows.
func (s *Scanner) uploadURL(body []byte, uploads string) string {
	for _, m := range srcHrefRe.FindAllSubmatch(body, -1) {
		u, err := s.base.Parse(html.UnescapeString(string(m[1])))
		if err == nil && strings.Contains(u.Path, uploads) && s.client.InScope(u) {
			return u.String()
		}
	}
	return ""
}

// httpURL keeps a URL only if it is an absolute http(s) URL.
func httpURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.String()
}

// MediaKind sorts a file into a kind for the report: image, document,
// archive or data, and so on.
func MediaKind(m *Media) string {
	mime := strings.ToLower(m.MimeType)
	ext := strings.ToLower(pathExt(m.URL))
	switch {
	case strings.HasPrefix(mime, "image/") || slices.Contains([]string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".avif", ".bmp", ".ico"}, ext):
		return "image"
	case strings.HasPrefix(mime, "video/") || strings.HasPrefix(mime, "audio/") || slices.Contains([]string{".mp4", ".mov", ".webm", ".mp3", ".wav", ".ogg", ".m4a"}, ext):
		return "audio or video"
	case slices.Contains([]string{".zip", ".gz", ".tgz", ".tar", ".rar", ".7z", ".sql", ".bak"}, ext) || strings.Contains(mime, "zip") || strings.Contains(mime, "sql"):
		return "archive or data"
	case m.URL == "" && mime == "":
		return "unknown"
	}
	return "document"
}

func pathExt(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	i := strings.LastIndexByte(u.Path, '.')
	if i < 0 || strings.Contains(u.Path[i:], "/") {
		return ""
	}
	return u.Path[i:]
}
