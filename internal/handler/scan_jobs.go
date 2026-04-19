package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"skill-scanner/internal/config"
	"skill-scanner/internal/docx"
	"skill-scanner/internal/evaluator"
	"skill-scanner/internal/llm"
	"skill-scanner/internal/models"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/sandbox"
	"skill-scanner/internal/storage"
)

func createScanJob(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
			return
		}

		sess := getSession(r)
		if sess == nil {
			sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "未登录"})
			return
		}

		tmpDir, originalName, description, permissions, err := saveScanUpload(r)
		if err != nil {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		user := store.GetUser(sess.Username)
		team := ""
		if user != nil {
			team = user.Team
		}

		jobID, err := storage.GenerateID()
		if err != nil {
			os.RemoveAll(tmpDir)
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "创建任务失败"})
			return
		}

		job := models.NewScanJob(jobID, sess.Username, team, originalName)
		if err := store.CreateScanJob(job); err != nil {
			os.RemoveAll(tmpDir)
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "保存任务失败"})
			return
		}

		go runScanJobAsync(store, jobID, sess.Username, team, originalName, tmpDir, description, permissions)

		sendJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"job_id":  jobID,
			"status":  string(models.ScanJobQueued),
		})
	}
}

func getScanJobStatus(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
			return
		}

		sess := getSession(r)
		if sess == nil {
			sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "未登录"})
			return
		}

		jobID := strings.TrimPrefix(r.URL.Path, "/api/scan/jobs/")
		jobID = filepath.Base(jobID)
		if jobID == "" || jobID == "." || jobID == "/" {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "无效任务ID"})
			return
		}

		if !store.CanAccessScanJob(sess.Username, jobID) {
			sendJSON(w, http.StatusForbidden, map[string]string{"error": "无权访问此任务"})
			return
		}

		job := store.GetScanJob(jobID)
		if job == nil {
			sendJSON(w, http.StatusNotFound, map[string]string{"error": "任务不存在"})
			return
		}

		sendJSON(w, http.StatusOK, map[string]interface{}{
			"id":          job.ID,
			"status":      string(job.Status),
			"progress":    job.Progress,
			"error":       job.Error,
			"report_id":   job.ReportID,
			"started_at":  job.StartedAt,
			"finished_at": job.FinishedAt,
			"duration_ms": job.DurationMs,
			"updated_at":  job.UpdatedAt,
		})
	}
}

func runScanJobAsync(store *storage.Store, jobID, username, team, originalName, tmpDir, description string, permissions []string) {
	defer os.RemoveAll(tmpDir)

	job := store.GetScanJob(jobID)
	if job == nil {
		return
	}
	job.Status = models.ScanJobRunning
	job.Progress = 10
	job.Error = ""
	job.StartedAt = time.Now().Unix()
	_ = store.UpdateScanJob(job)

	reportID, findingCount, err := executeScanPipeline(store, username, team, originalName, tmpDir, description, permissions)
	job = store.GetScanJob(jobID)
	if job == nil {
		return
	}
	if err != nil {
		job.Status = models.ScanJobFailed
		job.Progress = 100
		job.Error = err.Error()
		job.FinishedAt = time.Now().Unix()
		if job.StartedAt > 0 {
			job.DurationMs = (job.FinishedAt - job.StartedAt) * 1000
		}
		_ = store.UpdateScanJob(job)
		return
	}

	_ = findingCount
	job.Status = models.ScanJobSuccess
	job.Progress = 100
	job.ReportID = reportID
	job.Error = ""
	job.FinishedAt = time.Now().Unix()
	if job.StartedAt > 0 {
		job.DurationMs = (job.FinishedAt - job.StartedAt) * 1000
	}
	_ = store.UpdateScanJob(job)
}

func saveScanUpload(r *http.Request) (tmpDir, originalName, description string, permissions []string, err error) {
	if err = r.ParseMultipartForm(100 << 20); err != nil {
		return "", "", "", nil, fmt.Errorf("文件太大或解析失败")
	}
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		return "", "", "", nil, fmt.Errorf("请上传至少一个文件")
	}

	originalName = files[0].Filename
	if len(files) > 1 {
		originalName = fmt.Sprintf("%s 等 %d 个文件", originalName, len(files))
	}

	tmpDir, err = os.MkdirTemp("", "skill-scan-job-*")
	if err != nil {
		return "", "", "", nil, fmt.Errorf("创建临时目录失败")
	}

	for _, fh := range files {
		if fh.Size == 0 {
			continue
		}
		if !isSafeFilename(fh.Filename) {
			os.RemoveAll(tmpDir)
			return "", "", "", nil, fmt.Errorf("不支持的文件名")
		}
		relPath := filepath.Clean(fh.Filename)
		destPath := filepath.Join(tmpDir, relPath)
		if !storage.IsPathSafe(tmpDir, relPath) {
			os.RemoveAll(tmpDir)
			return "", "", "", nil, fmt.Errorf("文件路径不安全")
		}
		if err = os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			os.RemoveAll(tmpDir)
			return "", "", "", nil, fmt.Errorf("创建目录失败")
		}
		src, openErr := fh.Open()
		if openErr != nil {
			os.RemoveAll(tmpDir)
			return "", "", "", nil, fmt.Errorf("读取文件失败")
		}
		dst, createErr := os.Create(destPath)
		if createErr != nil {
			src.Close()
			os.RemoveAll(tmpDir)
			return "", "", "", nil, fmt.Errorf("保存文件失败")
		}
		_, copyErr := io.Copy(dst, src)
		src.Close()
		dst.Close()
		if copyErr != nil {
			os.RemoveAll(tmpDir)
			return "", "", "", nil, fmt.Errorf("写入文件失败")
		}
	}

	if err = validateExtractedFiles(tmpDir); err != nil {
		os.RemoveAll(tmpDir)
		return "", "", "", nil, err
	}

	description = r.FormValue("description")
	permissions = parsePermissions(r.FormValue("permissions"))
	return tmpDir, originalName, description, permissions, nil
}

func parsePermissions(permissionsStr string) []string {
	permissions := make([]string, 0)
	for _, p := range strings.Split(permissionsStr, ",") {
		if p = strings.TrimSpace(p); p != "" {
			permissions = append(permissions, p)
		}
	}
	return permissions
}

func executeScanPipeline(store *storage.Store, username, team, originalName, tmpDir, description string, permissions []string) (string, int, error) {
	var findings []plugins.Finding
	var evalResult *evaluator.EvaluationResult
	capabilityCfg := config.DefaultCapabilityFusionConfig()

	if globalEmbedder != nil && embedderInitError == nil {
		cfg, err := config.Load("config/rules.yaml")
		if err != nil {
			cfg = getDefaultConfig()
		} else {
			capabilityCfg = cfg.CapabilityFusion
		}
		var llmClient llm.Client
		userLLM := store.GetUserLLMConfig(username)
		if userLLM != nil && userLLM.Enabled && userLLM.APIKey != "" {
			switch userLLM.Provider {
			case "deepseek":
				llmClient = llm.NewDeepSeekClient(userLLM.APIKey)
			case "minimax":
				if userLLM.MiniMaxGroupID != "" {
					llmClient = llm.NewMiniMaxClient(userLLM.MiniMaxGroupID, userLLM.APIKey)
				}
			}
		}

		eval := evaluator.NewEvaluator(globalEmbedder, llmClient, cfg)
		var files []evaluator.SourceFile
		var dependencies []evaluator.Dependency

		_ = filepath.Walk(tmpDir, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil || info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			lang := ""
			switch ext {
			case ".go":
				lang = "go"
			case ".js":
				lang = "javascript"
			case ".ts":
				lang = "typescript"
			case ".py":
				lang = "python"
			default:
				return nil
			}

			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			content := string(data)
			files = append(files, evaluator.SourceFile{Path: path, Content: content, Language: lang})

			if filepath.Base(path) == "go.mod" {
				deps, depErr := parseGoMod(content)
				if depErr == nil {
					dependencies = append(dependencies, deps...)
				}
			}
			if filepath.Base(path) == "package.json" {
				var pkg struct {
					Dependencies map[string]string `json:"dependencies"`
				}
				if json.Unmarshal(data, &pkg) == nil {
					for name, version := range pkg.Dependencies {
						dependencies = append(dependencies, evaluator.Dependency{Name: name, Version: version})
					}
				}
			}
			return nil
		})

		depMap := make(map[string]evaluator.Dependency)
		for _, dep := range dependencies {
			key := dep.Name + "@" + dep.Version
			depMap[key] = dep
		}
		dependencies = make([]evaluator.Dependency, 0, len(depMap))
		for _, dep := range depMap {
			dependencies = append(dependencies, dep)
		}

		skill := &evaluator.Skill{
			Name:         originalName,
			Description:  description,
			Files:        files,
			Dependencies: dependencies,
			Permissions:  permissions,
		}

		evalResult, err = eval.EvaluateWithCascade(context.Background(), skill)
		if err == nil {
			findings = convertResultToFindings(evalResult, cfg)
		} else {
			findings = runPlugins(tmpDir)
		}
	} else {
		findings = runPlugins(tmpDir)
	}

	if sandbox.IsSandboxAvailable() {
		skillLang := sandbox.DetectLanguage(tmpDir)
		if skillLang != "" {
			sandboxCtx, sandboxCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer sandboxCancel()

			logs, sandboxErr := sandbox.RunSandbox(sandboxCtx, tmpDir, skillLang)
			if sandboxErr != nil {
				findings = append(findings, plugins.Finding{
					PluginName:  "DynamicSandbox",
					RuleID:      "DYN-001",
					Severity:    "中风险",
					Title:       "技能运行异常",
					Description: fmt.Sprintf("技能在隔离沙箱中运行时出错: %s", sandboxErr.Error()),
					Location:    tmpDir,
				})
			} else if sandbox.HasMaliciousIndicators("", logs.Logs) {
				findings = append(findings, plugins.Finding{
					PluginName:  "DynamicSandbox",
					RuleID:      "DYN-002",
					Severity:    "高风险",
					Title:       "检测到恶意运行行为",
					Description: "技能在沙箱运行时输出了可疑的恶意内容，可能尝试执行敏感系统操作",
					Location:    tmpDir,
					CodeSnippet: truncateString(logs.Logs, 500),
				})
			} else {
				findings = append(findings, plugins.Finding{
					PluginName:  "DynamicSandbox",
					RuleID:      "DYN-000",
					Severity:    "低风险",
					Title:       "动态沙箱扫描完成",
					Description: "技能在隔离沙箱中成功运行，未检测到明显恶意行为",
					Location:    tmpDir,
				})
			}
		}
	}

	reportFile := filepath.Join(tmpDir, "report.docx")
	gen := docx.NewGenerator()
	modelStatus, _, _ := GetModelStatus()
	llmEnabled := os.Getenv("DEEPSEEK_API_KEY") != ""
	score := 100.0
	if evalResult != nil {
		score = evalResult.Score
	}
	if err := gen.Generate(findings, score, modelStatus, llmEnabled, reportFile); err != nil {
		return "", 0, fmt.Errorf("生成报告失败")
	}

	reportID, err := storage.GenerateID()
	if err != nil {
		return "", 0, fmt.Errorf("生成报告ID失败")
	}
	reportFileName := fmt.Sprintf("report_%s.docx", reportID)
	reportDest := filepath.Join(store.ReportsDir(), reportFileName)
	if err := copyFile(reportFile, reportDest); err != nil {
		return "", 0, fmt.Errorf("保存报告失败")
	}

	extraDeclaredHints := make([]string, 0, 2)
	if evalResult != nil {
		if evalResult.LLMStatedIntent != "" {
			extraDeclaredHints = append(extraDeclaredHints, evalResult.LLMStatedIntent)
		}
		if evalResult.LLMActualBehavior != "" {
			extraDeclaredHints = append(extraDeclaredHints, evalResult.LLMActualBehavior)
		}
	}
	capability := buildCapabilityFusion(tmpDir, permissions, description, extraDeclaredHints, findings, capabilityCfg)
	findings = append(findings, buildCapabilityExplanationFindings(capability, capabilityCfg, originalName)...)
	if capability.Blocked {
		for _, reason := range capability.BlockReasons {
			findings = append(findings, plugins.Finding{
				PluginName:  "CapabilityFusion",
				RuleID:      "CAP-BLOCK",
				Severity:    "高风险",
				Title:       "能力融合触发阻断",
				Description: reason,
				Location:    originalName,
			})
		}
	}

	high, medium, low := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case "高风险":
			high++
		case "中风险":
			medium++
		default:
			low++
		}
	}
	reportFindings := make([]models.ReportFinding, 0, len(findings))
	for _, f := range findings {
		reportFindings = append(reportFindings, models.ReportFinding{
			PluginName:  f.PluginName,
			RuleID:      f.RuleID,
			Severity:    f.Severity,
			Title:       f.Title,
			Description: f.Description,
			Location:    f.Location,
			CodeSnippet: f.CodeSnippet,
		})
	}

	baseScore := 100.0
	riskLevel := "low"
	p0Blocked := capability.Blocked
	p0Reasons := append([]string{}, capability.BlockReasons...)
	itemScores := map[string]float64{}
	whitelistSuppressed := 0
	whitelistByRule := map[string]int{}
	llmStatedIntent := ""
	llmActualBehavior := ""
	llmIntentConfidence := 0
	if evalResult != nil {
		baseScore = evalResult.Score
		riskLevel = evalResult.RiskLevel
		whitelistSuppressed = evalResult.WhitelistSuppressed
		llmStatedIntent = evalResult.LLMStatedIntent
		llmActualBehavior = evalResult.LLMActualBehavior
		llmIntentConfidence = evalResult.LLMIntentConfidence
		for k, v := range evalResult.WhitelistByRule {
			whitelistByRule[k] = v
		}
		if evalResult.P0Blocked {
			p0Blocked = true
			p0Reasons = append(p0Reasons, evalResult.P0Reasons...)
		}
		for k, v := range evalResult.ItemScores {
			itemScores[k] = v
		}
	}

	baseWeight, capabilityWeight := normalizeFusionWeights(
		capabilityCfg.ScoreFusion.BaseWeight,
		capabilityCfg.ScoreFusion.CapabilityWeight,
	)
	finalScore := baseScore*baseWeight + capability.Score*capabilityWeight
	if finalScore < 0 {
		finalScore = 0
	}
	if finalScore > 100 {
		finalScore = 100
	}
	if capability.RiskLevel == "critical" {
		riskLevel = "critical"
	} else if capability.RiskLevel == "high" && riskLevel != "critical" {
		riskLevel = "high"
	} else if capability.RiskLevel == "medium" && riskLevel == "low" {
		riskLevel = "medium"
	}

	rep := &models.Report{
		ID:                  reportID,
		Username:            username,
		Team:                team,
		FileName:            originalName,
		FilePath:            reportFileName,
		CreatedAt:           time.Now().Unix(),
		FindingCount:        len(findings),
		HighRisk:            high,
		MediumRisk:          medium,
		LowRisk:             low,
		NoRisk:              len(findings) == 0,
		Findings:            reportFindings,
		Capability:          capability,
		BaseScore:           baseScore,
		CapabilityScore:     capability.Score,
		BaseWeight:          baseWeight,
		CapabilityWeight:    capabilityWeight,
		Score:               finalScore,
		RiskLevel:           riskLevel,
		P0Blocked:           p0Blocked,
		P0Reasons:           p0Reasons,
		WhitelistSuppressed: whitelistSuppressed,
		WhitelistByRule:     whitelistByRule,
		ItemScores:          itemScores,
		LLMStatedIntent:     llmStatedIntent,
		LLMActualBehavior:   llmActualBehavior,
		LLMIntentConfidence: llmIntentConfidence,
	}
	if err := store.AddReport(rep); err != nil {
		return "", 0, fmt.Errorf("保存报告记录失败")
	}

	return reportID, len(findings), nil
}

func buildCapabilityExplanationFindings(capability *models.CapabilityFusion, cfg config.CapabilityFusionConfig, location string) []plugins.Finding {
	if capability == nil {
		return nil
	}
	findings := make([]plugins.Finding, 0, len(capability.Overreach)+len(capability.Underdeclare))
	declaredCaps := "无"
	if len(capability.Declared) > 0 {
		declaredCaps = strings.Join(capability.Declared, ",")
	}
	observedCaps := "无"
	if len(capability.Observed) > 0 {
		observedCaps = strings.Join(capability.Observed, ",")
	}
	blockSet := make(map[string]bool)
	for _, capID := range cfg.BlockOnOverreach {
		blockSet[capID] = true
	}
	for _, capID := range capability.Overreach {
		capName, riskCategory := capabilityDisplayMeta(capID, cfg)
		severity := "中风险"
		reason := "检测到未声明能力"
		if blockSet[capID] {
			severity = "高风险"
			reason = "检测到高敏未声明能力"
		}
		conf := capability.ObservedConfidence[capID]
		desc := fmt.Sprintf("风险类别: %s；能力: %s(%s)；%s，观测置信度 %.2f。声明能力: %s；观测能力: %s。建议补充该能力的业务目的、数据边界和风险控制措施。", riskCategory, capName, capID, reason, conf, declaredCaps, observedCaps)
		findings = append(findings, plugins.Finding{
			PluginName:  "CapabilityFusion",
			RuleID:      "CAP-OVERREACH",
			Severity:    severity,
			Title:       "能力声明与行为不一致",
			Description: desc,
			Location:    location,
		})
	}
	for _, capID := range capability.Underdeclare {
		capName, riskCategory := capabilityDisplayMeta(capID, cfg)
		findings = append(findings, plugins.Finding{
			PluginName:  "CapabilityFusion",
			RuleID:      "CAP-UNDERDECLARE",
			Severity:    "低风险",
			Title:       "能力声明可能不完整",
			Description: fmt.Sprintf("风险类别: %s；能力: %s(%s)；声明了该能力但在代码中未观测到对应实现信号。声明能力: %s；观测能力: %s。建议核对文档声明是否过期或补充实现证据。", riskCategory, capName, capID, declaredCaps, observedCaps),
			Location:    location,
		})
	}
	return findings
}

func capabilityDisplayMeta(capID string, cfg config.CapabilityFusionConfig) (string, string) {
	for _, capCfg := range cfg.Capabilities {
		if capCfg.ID != capID {
			continue
		}
		name := strings.TrimSpace(capCfg.DisplayName)
		if name == "" {
			name = capID
		}
		category := strings.TrimSpace(capCfg.RiskCategory)
		if category == "" {
			category = "能力行为一致性"
		}
		return name, category
	}
	return capID, "能力行为一致性"
}

func normalizeFusionWeights(baseWeight, capabilityWeight float64) (float64, float64) {
	if baseWeight < 0 {
		baseWeight = 0
	}
	if capabilityWeight < 0 {
		capabilityWeight = 0
	}
	total := baseWeight + capabilityWeight
	if total <= 0 {
		return 0.65, 0.35
	}
	return baseWeight / total, capabilityWeight / total
}
