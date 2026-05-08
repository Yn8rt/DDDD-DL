package http

import (
	"dddd/structs"
	"fmt"
	"strconv"

	"github.com/projectdiscovery/httpx/runner"
)

func normalizeURLPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func cacheResponseHashes(resp runner.Result) (string, string) {
	md5 := getBodyHash(resp)
	headerMd5 := safeHashString(resp, "header_md5")
	if md5 != "" {
		_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
	}
	if headerMd5 != "" {
		_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))
	}
	return md5, headerMd5
}

func getBodyHash(resp runner.Result) string {
	return safeHashString(resp, "body_md5")
}

// safeHashString 安全读取 httpx Hashes map
// 防止 httpx 升级 key 名变动导致 panic
func safeHashString(resp runner.Result, key string) string {
	if resp.Hashes == nil {
		return ""
	}
	raw, ok := resp.Hashes[key]
	if !ok {
		return ""
	}
	s, ok := raw.(string)
	if !ok {
		return ""
	}
	return s
}

func StoreURLResult(resp runner.Result, rawURL string) bool {
	return upsertURLResult(resp, rawURL)
}

func buildURLPathEntity(resp runner.Result, md5, headerMd5 string) structs.UrlPathEntity {
	return structs.UrlPathEntity{
		Hash:             md5,
		Title:            resp.Title,
		StatusCode:       resp.StatusCode,
		ContentType:      resp.ContentType,
		Server:           resp.WebServer,
		ContentLength:    resp.ContentLength,
		HeaderHashString: headerMd5,
		IconHash:         resp.FavIconMMH3,
	}
}

func upsertURLResult(resp runner.Result, rawURL string) bool {
	parsedURL := URLParse(rawURL)
	path := normalizeURLPath(parsedURL.Path)
	rootURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	md5, headerMd5 := cacheResponseHashes(resp)
	webPath := buildURLPathEntity(resp, md5, headerMd5)

	port, err := strconv.Atoi(resp.Port)
	if err != nil {
		port = 0
	}

	structs.GlobalURLMapLock.Lock()
	defer structs.GlobalURLMapLock.Unlock()

	urlEntry, ok := structs.GlobalURLMap[rootURL]
	if !ok {
		structs.GlobalURLMap[rootURL] = structs.URLEntity{
			IP:   resp.Host,
			Port: port,
			WebPaths: map[string]structs.UrlPathEntity{
				path: webPath,
			},
			Cert: getTLSString(resp),
		}
		return true
	}

	if urlEntry.WebPaths == nil {
		urlEntry.WebPaths = make(map[string]structs.UrlPathEntity)
	}

	if _, exists := urlEntry.WebPaths[path]; exists {
		return false
	}

	urlEntry.WebPaths[path] = webPath
	structs.GlobalURLMap[rootURL] = urlEntry
	return true
}
