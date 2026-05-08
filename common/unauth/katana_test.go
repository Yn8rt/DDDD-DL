package unauth

import (
	"testing"

	"github.com/projectdiscovery/httpx/runner"
)

func TestCollectCandidateParts(t *testing.T) {
	discovered := []katanaDiscoveredURL{
		{URL: "http://example.com/api/user/list", Evidence: "xhr"},
		{URL: "http://example.com/admin/config", Evidence: "script"},
		{URL: "http://example.com/captcha", Evidence: "img"},
		{URL: "http://example.com/static/app.js", Evidence: "script"},
		{URL: "http://example.com/%27+t.content[0]+%27", Evidence: "get"},
	}

	absolutePaths, firstLevelDirs, relativePaths := collectCandidateParts("http://example.com", discovered)

	assertStringMapKeysEqual(t, absolutePaths, []string{"/admin/config", "/api/user/list"})
	assertStringMapKeysEqual(t, firstLevelDirs, []string{"/admin", "/api"})
	assertStringMapKeysEqual(t, relativePaths, []string{"/config", "/user/list"})
}

func TestIsPotentialUnauthorized(t *testing.T) {
	detector := &probeDetector{
		baselines: map[string]baselineProfile{
			"http://example.com": {
				loginHashes: map[string]struct{}{"login-hash": {}},
				loginTitles: map[string]struct{}{"用户登录": {}},
			},
		},
	}

	successResp := runner.Result{
		URL:         "http://example.com/api/users",
		StatusCode:  200,
		ContentType: "application/json",
		Body:        `{"ok":true}`,
		Hashes:      map[string]interface{}{"body_md5": "api-hash"},
	}
	if !detector.isPotentialUnauthorized(successResp, successResp.URL) {
		t.Fatalf("expected json api response to be treated as potential unauthorized target")
	}

	loginResp := runner.Result{
		URL:         "http://example.com/api/users",
		FinalURL:    "http://example.com/login",
		StatusCode:  200,
		ContentType: "text/html",
		Title:       "用户登录",
		Hashes:      map[string]interface{}{"body_md5": "login-hash"},
	}
	if detector.isPotentialUnauthorized(loginResp, loginResp.FinalURL) {
		t.Fatalf("expected login-like response to be filtered")
	}

	staticJSONResp := runner.Result{
		URL:         "http://example.com/version.json",
		StatusCode:  200,
		ContentType: "application/json",
		Body:        `{"version":"1.0.0"}`,
		Hashes:      map[string]interface{}{"body_md5": "version-hash"},
	}
	if detector.isPotentialUnauthorized(staticJSONResp, staticJSONResp.URL) {
		t.Fatalf("expected version.json to be treated as static data, not api unauthorized target")
	}
}

func assertStringMapKeysEqual(t *testing.T, actual map[string]string, expected []string) {
	t.Helper()
	actualKeys := setToSortedStringMapKeys(actual)
	if len(actualKeys) != len(expected) {
		t.Fatalf("slice length mismatch, got=%v want=%v", actualKeys, expected)
	}
	for i := range actualKeys {
		if actualKeys[i] != expected[i] {
			t.Fatalf("slice item mismatch, got=%v want=%v", actualKeys, expected)
		}
	}
}
