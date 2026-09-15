package main

import (
	"dddd/internal/structs"
	"testing"
)

func TestWorkflowPocsForSearchMatchesProductAndDeduplicates(t *testing.T) {
	original := structs.WorkFlowDB
	defer func() { structs.WorkFlowDB = original }()

	structs.WorkFlowDB = map[string]structs.WorkFlowEntity{
		"H3C-F1000":  {PocsName: []string{"CVE-2026-15907", "shared-poc"}},
		"H3C-ER5200": {PocsName: []string{"shared-poc", "router-poc"}},
		"Apache":     {PocsName: []string{"apache-poc"}},
	}

	got := workflowPocsForSearch("  h3c ")
	if len(got) != 3 {
		t.Fatalf("workflowPocsForSearch() returned %d POCs, want 3: %v", len(got), got)
	}

	seen := make(map[string]bool, len(got))
	for _, poc := range got {
		seen[poc] = true
	}
	for _, poc := range []string{"CVE-2026-15907", "shared-poc", "router-poc"} {
		if !seen[poc] {
			t.Errorf("workflowPocsForSearch() missing %q: %v", poc, got)
		}
	}
}

func TestWorkflowPocsForSearchEmptyQuery(t *testing.T) {
	original := structs.WorkFlowDB
	defer func() { structs.WorkFlowDB = original }()

	structs.WorkFlowDB = map[string]structs.WorkFlowEntity{
		"H3C-F1000": {PocsName: []string{"CVE-2026-15907"}},
	}
	if got := workflowPocsForSearch(" "); len(got) != 0 {
		t.Fatalf("workflowPocsForSearch() with empty query = %v, want empty", got)
	}
}
