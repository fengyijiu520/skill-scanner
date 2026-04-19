package handler

import (
	"os"
	"path/filepath"
	"testing"

	"skill-scanner/internal/config"
	"skill-scanner/internal/plugins"
)

func TestInferDeclaredFromSkillDocs(t *testing.T) {
	tmp := t.TempDir()
	skillDoc := "# Skill\nThis skill can read files, write files, execute command and call HTTP API."
	if err := os.WriteFile(filepath.Join(tmp, "SKILL.md"), []byte(skillDoc), 0644); err != nil {
		t.Fatalf("write skill doc failed: %v", err)
	}

	cfg := config.DefaultCapabilityFusionConfig()
	declared := inferDeclaredFromSkillDocs(tmp, cfg)
	set := make(map[string]bool)
	for _, capID := range declared {
		set[capID] = true
	}
	for _, expect := range []string{"file_read", "file_write", "code_exec", "net_outbound"} {
		if !set[expect] {
			t.Fatalf("expected declared capability %s from skill docs, got %v", expect, declared)
		}
	}
}

func TestBuildCapabilityFusionUsesExtraDeclaredHints(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "README.md"), []byte("safe helper"), 0644); err != nil {
		t.Fatalf("write readme failed: %v", err)
	}

	cfg := config.DefaultCapabilityFusionConfig()
	fusion := buildCapabilityFusion(
		tmp,
		nil,
		"",
		[]string{"this agent can execute command and call network api"},
		[]plugins.Finding{{RuleID: "P0-001", Title: "exec.command", Description: "command execution observed"}},
		cfg,
	)

	declaredSet := make(map[string]bool)
	for _, capID := range fusion.Declared {
		declaredSet[capID] = true
	}
	if !declaredSet["code_exec"] {
		t.Fatalf("expected code_exec declared by extra hints, got %v", fusion.Declared)
	}
	if !declaredSet["net_outbound"] {
		t.Fatalf("expected net_outbound declared by extra hints, got %v", fusion.Declared)
	}
}
