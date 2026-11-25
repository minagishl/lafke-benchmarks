package main

import "testing"

func TestKICSQueryMatchesSameIssue(t *testing.T) {
	const rule = "sast:iac/open-ingress"
	const file = "case/main.tf"
	m, err := compileKICSFilters("", map[string][]string{"http": {rule}}, map[string]kicsFilter{"http": {Port: 80}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		detail string
		want   bool
	}{
		{"RDP (3389) is exposed. TCP ports 3389-3389 are open to 0.0.0.0/0", false},
		{"TCP ports 70-120 are open to 0.0.0.0/0", true},
		{"UDP ports 70-120 are open to ::/0", false},
		{"TCP ports 80-80 are open to 192.0.2.0/0", false},
		{"all protocols and ports are open to ::/0 (configured ports 3389-3389)", true},
	} {
		if hit := m["http"].matches(finding{Detail: tt.detail}); hit != tt.want {
			t.Errorf("%q: got %t, want %t", tt.detail, hit, tt.want)
		}
	}
	cases := []kicsCase{
		{file: file, rules: map[string]bool{rule: true}, real: false, match: m["http"]},
		{file: file, rules: map[string]bool{rule: true}, real: true, match: m["http"]},
	}
	score, err := (kicsSuite{}).score(nil, nil, []unit{{Name: "aws", Meta: &kicsMeta{cases: cases}}}, map[string]*unitResult{
		"aws": {findings: []finding{{ID: rule, File: file, Detail: "TCP ports 3389-3389 are open to 0.0.0.0/0"}}},
	})
	if err != nil || score.FP != 0 || score.FN != 1 {
		t.Fatalf("unrelated finding must match neither case: %+v, %v", score, err)
	}
}

func TestKICSConfiguredPorts(t *testing.T) {
	for _, tt := range []struct {
		category, detail string
		want             bool
	}{
		{"known", "TCP ports 22-22 are open to 192.0.2.0/0", true},
		{"unknown", "TCP ports 22-22 are open to ::/0", false},
		{"unknown", "TCP ports 21-22 are open to 0.0.0.0/0", true},
		{"unknown", "all protocols and ports are open to ::/0 (configured ports 22-22)", false},
	} {
		m := kicsMatcher{filter: kicsFilter{Ports: tt.category}, knownPorts: map[int]bool{22: true}}
		if m.matches(finding{Detail: tt.detail}) != tt.want {
			t.Errorf("%s, %q: expected %t", tt.category, tt.detail, tt.want)
		}
	}
}

func TestKICSMatchesSpecificSettingsAndResources(t *testing.T) {
	const rule = "sast:iac/public-bucket"
	const q = "s3_bucket_with_public_policy"
	filters := map[string]kicsFilter{q: {
		Detail:        "^block_public_policy ",
		ExcludeDetail: "account-level protection is enabled|bucket-level access blocks are declared",
		Subject:       "#aws_s3_(?:account|bucket)_public_access_block\\.",
	}}
	m, err := compileKICSFilters("", map[string][]string{q: {rule}}, filters)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		detail, subject string
		want            bool
	}{
		{"block_public_policy is false", "main.tf#aws_s3_bucket_public_access_block.test", true},
		{"block_public_policy is false", "main.tf#module.other", false},
		{"ignore_public_acls is false", "main.tf#aws_s3_bucket_public_access_block.test", false},
		{"block_public_policy is false; account-level protection is enabled in this provider configuration", "main.tf#aws_s3_bucket_public_access_block.test", false},
		{"block_public_policy is unset and defaults to false", "main.tf#aws_s3_account_public_access_block.test", true},
	} {
		if m[q].matches(finding{ID: rule, Detail: tt.detail, Subject: tt.subject}) != tt.want {
			t.Errorf("%q in %s: expected %t", tt.detail, tt.subject, tt.want)
		}
	}
}
