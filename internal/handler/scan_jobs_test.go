package handler

import (
	"strings"
	"testing"

	"skill-scanner/internal/config"
	"skill-scanner/internal/models"
)

func TestBuildCapabilityExplanationFindingsOverreachSeverity(t *testing.T) {
	cfg := config.DefaultCapabilityFusionConfig()
	cfg.BlockOnOverreach = []string{"filesystem_write"}

	capability := &models.CapabilityFusion{
		Overreach: []string{"filesystem_write", "network_access"},
		ObservedConfidence: map[string]float64{
			"filesystem_write": 0.9,
			"network_access":   0.6,
		},
	}

	findings := buildCapabilityExplanationFindings(capability, cfg, "skill.zip")
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	sevByCap := map[string]string{}
	for _, f := range findings {
		if f.RuleID != "CAP-OVERREACH" {
			t.Fatalf("expected CAP-OVERREACH, got %s", f.RuleID)
		}
		if f.Location != "skill.zip" {
			t.Fatalf("expected location skill.zip, got %s", f.Location)
		}
		if f.Severity == "高风险" {
			sevByCap["filesystem_write"] = f.Severity
		}
		if f.Severity == "中风险" {
			sevByCap["network_access"] = f.Severity
		}
	}

	if sevByCap["filesystem_write"] != "高风险" {
		t.Fatalf("expected filesystem_write to be 高风险")
	}
	if sevByCap["network_access"] != "中风险" {
		t.Fatalf("expected network_access to be 中风险")
	}
}

func TestBuildCapabilityExplanationFindingsUnderdeclare(t *testing.T) {
	cfg := config.DefaultCapabilityFusionConfig()
	capability := &models.CapabilityFusion{
		Underdeclare: []string{"process_exec"},
	}

	findings := buildCapabilityExplanationFindings(capability, cfg, "skill.zip")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "CAP-UNDERDECLARE" {
		t.Fatalf("expected CAP-UNDERDECLARE, got %s", f.RuleID)
	}
	if f.Severity != "低风险" {
		t.Fatalf("expected 低风险, got %s", f.Severity)
	}
}

func TestBuildCapabilityExplanationFindingsUsesConfiguredCapabilityMeta(t *testing.T) {
	cfg := config.DefaultCapabilityFusionConfig()
	for i := range cfg.Capabilities {
		if cfg.Capabilities[i].ID == "net_outbound" {
			cfg.Capabilities[i].DisplayName = "外部网络通信"
			cfg.Capabilities[i].RiskCategory = "网络访问风险"
		}
	}

	capability := &models.CapabilityFusion{
		Overreach: []string{"net_outbound"},
		ObservedConfidence: map[string]float64{
			"net_outbound": 0.8,
		},
	}

	findings := buildCapabilityExplanationFindings(capability, cfg, "skill.zip")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	desc := findings[0].Description
	if !strings.Contains(desc, "外部网络通信") || !strings.Contains(desc, "网络访问风险") {
		t.Fatalf("expected configured display name and category in description, got %s", desc)
	}
}
