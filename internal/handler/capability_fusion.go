package handler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"skill-scanner/internal/config"
	"skill-scanner/internal/models"
	"skill-scanner/internal/plugins"
)

func buildCapabilityFusion(tmpDir string, permissions []string, description string, extraDeclaredHints []string, findings []plugins.Finding, cfg config.CapabilityFusionConfig) *models.CapabilityFusion {
	if len(cfg.Capabilities) == 0 {
		cfg = config.DefaultCapabilityFusionConfig()
	}

	declaredSet := make(map[string]bool)
	observedSet := make(map[string]bool)
	observedConfidence := make(map[string]float64)
	weights := capabilityWeights(cfg)

	for _, p := range permissions {
		if capID := mapDeclaredCapability(p, cfg); capID != "" {
			declaredSet[capID] = true
		}
	}
	for _, capID := range inferDeclaredFromDescription(description, cfg) {
		declaredSet[capID] = true
	}
	for _, capID := range inferDeclaredFromSkillDocs(tmpDir, cfg) {
		declaredSet[capID] = true
	}
	for _, hint := range extraDeclaredHints {
		for _, capID := range inferDeclaredFromDescription(hint, cfg) {
			declaredSet[capID] = true
		}
	}

	for capID, confidence := range inferObservedFromFiles(tmpDir, cfg) {
		observedSet[capID] = true
		observedConfidence[capID] = maxFloat(observedConfidence[capID], confidence)
	}
	for capID, confidence := range inferObservedFromFindings(findings, cfg) {
		observedSet[capID] = true
		observedConfidence[capID] = maxFloat(observedConfidence[capID], confidence)
	}

	declared := sortedKeys(declaredSet)
	observed := sortedKeys(observedSet)

	matchedSet := make(map[string]bool)
	overreachSet := make(map[string]bool)
	underdeclareSet := make(map[string]bool)

	for _, capID := range observed {
		if declaredSet[capID] {
			matchedSet[capID] = true
		} else {
			overreachSet[capID] = true
		}
	}
	for _, capID := range declared {
		if !observedSet[capID] {
			underdeclareSet[capID] = true
		}
	}

	matched := sortedKeys(matchedSet)
	overreach := sortedKeys(overreachSet)
	underdeclare := sortedKeys(underdeclareSet)

	risk := 0.0
	maxRisk := 0.0
	for capID, w := range weights {
		maxRisk += w * cfg.OverreachMultiplier
		if overreachSet[capID] {
			conf := observedConfidence[capID]
			if conf <= 0 {
				conf = 0.6
			}
			risk += w * cfg.OverreachMultiplier * conf
		}
		if underdeclareSet[capID] {
			risk += w * cfg.UnderdeclarePenalty
		}
		if matchedSet[capID] {
			risk -= w * cfg.MatchBonus
		}
	}
	if risk < 0 {
		risk = 0
	}
	riskScore := 0.0
	if maxRisk > 0 {
		riskScore = risk / maxRisk * 100
	}

	score := cfg.ScoreBase - riskScore
	if score < 0 {
		score = 0
	}

	riskLevel := "low"
	if riskScore >= cfg.Thresholds.Critical {
		riskLevel = "critical"
	} else if riskScore >= cfg.Thresholds.High {
		riskLevel = "high"
	} else if riskScore >= cfg.Thresholds.Medium {
		riskLevel = "medium"
	}

	blocked := false
	blockReasons := make([]string, 0)
	if riskScore >= cfg.Thresholds.Critical {
		blocked = true
		blockReasons = append(blockReasons, fmt.Sprintf("能力融合风险得分 %.1f 达到 critical 阈值 %.1f", riskScore, cfg.Thresholds.Critical))
	}
	blockSet := make(map[string]bool)
	for _, capID := range cfg.BlockOnOverreach {
		blockSet[capID] = true
	}
	for _, capID := range overreach {
		if blockSet[capID] {
			blocked = true
			blockReasons = append(blockReasons, "出现高敏超声明能力: "+capID)
		}
	}

	return &models.CapabilityFusion{
		Declared:           declared,
		Observed:           observed,
		Matched:            matched,
		Overreach:          overreach,
		Underdeclare:       underdeclare,
		ObservedConfidence: observedConfidence,
		Score:              score,
		RiskScore:          riskScore,
		RiskLevel:          riskLevel,
		Blocked:            blocked,
		BlockReasons:       blockReasons,
	}
}

func mapDeclaredCapability(raw string, cfg config.CapabilityFusionConfig) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	for _, capCfg := range cfg.Capabilities {
		for _, k := range capCfg.DeclaredKeywords {
			if strings.Contains(v, strings.ToLower(k)) {
				return capCfg.ID
			}
		}
	}
	return ""
}

func inferDeclaredFromDescription(description string, cfg config.CapabilityFusionConfig) []string {
	v := strings.ToLower(description)
	set := make(map[string]bool)
	for _, capCfg := range cfg.Capabilities {
		for _, k := range capCfg.DeclaredKeywords {
			if strings.Contains(v, strings.ToLower(k)) {
				set[capCfg.ID] = true
				break
			}
		}
	}
	return sortedKeys(set)
}

func inferDeclaredFromSkillDocs(tmpDir string, cfg config.CapabilityFusionConfig) []string {
	set := make(map[string]bool)
	targets := []string{"skill.md", "readme.md", "_meta.json", "agent.yaml", "agent.yml"}
	_ = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if info.Size() > 2*1024*1024 {
			return nil
		}
		base := strings.ToLower(filepath.Base(path))
		matched := false
		for _, t := range targets {
			if base == t {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		text := extractDeclarationText(base, b)
		for _, capID := range inferDeclaredFromDescription(text, cfg) {
			set[capID] = true
		}
		return nil
	})
	return sortedKeys(set)
}

func extractDeclarationText(base string, content []byte) string {
	if base == "_meta.json" {
		var meta map[string]interface{}
		if json.Unmarshal(content, &meta) == nil {
			parts := make([]string, 0, 6)
			for _, k := range []string{"description", "skill_name", "summary", "permissions", "capabilities"} {
				if v, ok := meta[k]; ok {
					parts = append(parts, fmt.Sprintf("%v", v))
				}
			}
			if len(parts) > 0 {
				return strings.Join(parts, "\n")
			}
		}
	}
	text := strings.ToLower(string(content))
	lines := strings.Split(text, "\n")
	out := make([]string, 0, 32)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "*") {
			out = append(out, line)
			continue
		}
		if strings.Contains(line, "permission") || strings.Contains(line, "capabil") || strings.Contains(line, "feature") || strings.Contains(line, "ability") || strings.Contains(line, " can ") || strings.Contains(line, " will ") || strings.Contains(line, "支持") || strings.Contains(line, "能力") || strings.Contains(line, "权限") {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return text
	}
	return strings.Join(out, "\n")
}

func inferObservedFromFiles(tmpDir string, cfg config.CapabilityFusionConfig) map[string]float64 {
	set := make(map[string]float64)
	_ = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".go", ".js", ".ts", ".py":
		default:
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		lines := strings.Split(string(b), "\n")
		lineCommentPrefix := commentPrefixByExt(ext)
		fileWeight := signalWeightByFile(path, ext)
		for _, capCfg := range cfg.Capabilities {
			matchWeight := 0.0
			for _, line := range lines {
				normalized := normalizeCodeLine(line, lineCommentPrefix)
				if normalized == "" {
					continue
				}
				if containsNoise(normalized, capCfg.NoiseKeywords) {
					continue
				}
				for _, k := range capCfg.ObservedKeywords {
					if keywordMatched(normalized, k) {
						matchWeight += fileWeight
						break
					}
				}
			}
			if matchWeight >= 1.8 {
				set[capCfg.ID] = maxFloat(set[capCfg.ID], 0.82)
			} else if matchWeight >= 1.0 {
				set[capCfg.ID] = maxFloat(set[capCfg.ID], 0.75)
			} else if matchWeight >= 0.5 {
				set[capCfg.ID] = maxFloat(set[capCfg.ID], 0.55)
			}
		}
		return nil
	})
	return set
}

func inferObservedFromFindings(findings []plugins.Finding, cfg config.CapabilityFusionConfig) map[string]float64 {
	set := make(map[string]float64)
	for _, f := range findings {
		v := strings.ToLower(f.RuleID + " " + f.Title + " " + f.Description)
		for _, capCfg := range cfg.Capabilities {
			for _, k := range capCfg.FindingKeywords {
				if strings.Contains(v, strings.ToLower(k)) {
					set[capCfg.ID] = maxFloat(set[capCfg.ID], 0.85)
					break
				}
			}
		}
	}
	return set
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func capabilityWeights(cfg config.CapabilityFusionConfig) map[string]float64 {
	out := make(map[string]float64)
	for _, capCfg := range cfg.Capabilities {
		w := capCfg.Weight
		if w <= 0 {
			w = 1
		}
		out[capCfg.ID] = w
	}
	return out
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func commentPrefixByExt(ext string) string {
	switch ext {
	case ".py":
		return "#"
	default:
		return "//"
	}
}

func normalizeCodeLine(line, commentPrefix string) string {
	v := strings.TrimSpace(strings.ToLower(line))
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, commentPrefix) || strings.HasPrefix(v, "*") || strings.HasPrefix(v, "/*") {
		return ""
	}
	if i := strings.Index(v, commentPrefix); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v
}

func containsNoise(line string, noiseKeywords []string) bool {
	for _, k := range noiseKeywords {
		if strings.Contains(line, strings.ToLower(strings.TrimSpace(k))) {
			return true
		}
	}
	return false
}

func keywordMatched(line, keyword string) bool {
	k := strings.ToLower(strings.TrimSpace(keyword))
	if k == "" {
		return false
	}
	if strings.ContainsAny(k, "(.[") {
		return strings.Contains(line, k)
	}
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(k) + `\b`)
	return re.MatchString(line)
}

func signalWeightByFile(path, ext string) float64 {
	w := 1.0
	switch ext {
	case ".ts", ".js":
		w = 0.9
	case ".py":
		w = 0.85
	}
	p := strings.ToLower(path)
	if isTestLikePath(p) {
		w *= 0.45
	}
	if strings.Contains(p, "/examples/") || strings.Contains(p, "/example/") || strings.Contains(p, "/mock/") || strings.Contains(p, "/mocks/") {
		w *= 0.7
	}
	return w
}

func isTestLikePath(path string) bool {
	base := filepath.Base(path)
	return strings.Contains(path, "/test/") || strings.Contains(path, "/tests/") || strings.HasSuffix(base, "_test.go") || strings.Contains(base, ".spec.") || strings.Contains(base, ".test.")
}
