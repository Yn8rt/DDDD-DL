package backup

import "testing"

func TestBuildBackupNamesIncludesCompatibleDomainPatterns(t *testing.T) {
	names := BuildBackupNames("www.baidu.com", []string{"zip", "tar.gz"})
	wants := []string{
		"www_baidu_com.zip",
		"www_baidu.com_com.tar.gz",
		"baidu_com.zip",
		"baidu.com.tar.gz",
	}

	for _, want := range wants {
		if !contains(names, want) {
			t.Fatalf("BuildBackupNames() missing %q in %v", want, names)
		}
	}
}

func TestBuildCandidatesNormalizesRootURLAndDeduplicates(t *testing.T) {
	got := BuildCandidates([]string{"https://www.baidu.com:8443/app", "https://www.baidu.com:8443/"}, []string{"zip"})
	if len(got) == 0 {
		t.Fatalf("BuildCandidates() returned no candidates")
	}
	if got[0].Root != "https://www.baidu.com:8443" {
		t.Fatalf("Root = %q, want https://www.baidu.com:8443", got[0].Root)
	}

	seen := make(map[string]struct{})
	for _, item := range got {
		if _, ok := seen[item.URL]; ok {
			t.Fatalf("duplicate candidate URL: %s", item.URL)
		}
		seen[item.URL] = struct{}{}
	}
}

func TestIsBackupHitFiltersSoft404Baseline(t *testing.T) {
	probe := probeResult{StatusCode: 200, ContentLength: 1234, ContentType: "text/html"}
	baseline := probeResult{StatusCode: 200, ContentLength: 1234, ContentType: "text/html"}
	if isBackupHit(probe, baseline) {
		t.Fatalf("expected soft 404-like response to be filtered")
	}
}

func TestIsBackupHitAcceptsArchiveResponse(t *testing.T) {
	probe := probeResult{StatusCode: 200, ContentLength: 4096, ContentType: "application/zip"}
	baseline := probeResult{StatusCode: 404, ContentLength: 0, ContentType: "text/html"}
	if !isBackupHit(probe, baseline) {
		t.Fatalf("expected archive-like response to be treated as backup hit")
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
