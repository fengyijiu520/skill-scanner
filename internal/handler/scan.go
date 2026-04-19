package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/mod/modfile"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"skill-scanner/internal/analyzer"
	"skill-scanner/internal/config"
	"skill-scanner/internal/docx"
	"skill-scanner/internal/embedder"
	"skill-scanner/internal/evaluator"
	"skill-scanner/internal/llm"
	"skill-scanner/internal/models"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/sandbox"
	"skill-scanner/internal/storage"
	"strings"
	"time"
)

// -------- 全局嵌入器单例 --------
var (
	globalEmbedder    *embedder.BgeOnnxEmbedder
	embedderInitError error
	embedderModelName = "BGE-M3 (ONNX)"
)

// InitEmbedder 在程序启动时调用一次，初始化 ONNX 嵌入器。
// 应在 main 函数中调用，并将结果传递给 handler 包。
func InitEmbedder() {
	log.Println("正在加载 BGE 嵌入器...")
	globalEmbedder, embedderInitError = embedder.NewBgeOnnxEmbedder()
	if embedderInitError != nil {
		log.Printf("❌ BGE 嵌入器初始化失败: %v", embedderInitError)
		embedderModelName = "基础规则 (模型加载失败)"
	} else {
		log.Println("✅ BGE 嵌入器初始化成功")
	}
}

// GetModelStatus 返回当前引擎状态，供模板渲染。
func GetModelStatus() (status string, hasError bool, errorMsg string) {
	if embedderInitError != nil {
		return embedderModelName, true, embedderInitError.Error()
	}
	if globalEmbedder == nil {
		return "基础规则 (未初始化)", true, "模型未初始化"
	}
	return "🔬 BGE-M3 语义引擎", false, ""
}

// scan handles the skill scanning page and report generation.
func scan(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		user := store.GetUser(sess.Username)
		userPerms := map[string]bool{
			"HasPersonal": false,
			"HasUserMgmt": false,
			"HasLogPerm":  false,
		}
		if user != nil {
			userPerms["HasPersonal"] = user.HasPermission(models.PermPersonalCenter)
			userPerms["HasUserMgmt"] = user.HasPermission(models.PermUserManagement)
			userPerms["HasLogPerm"] = user.HasPermission(models.PermLoginLog)
		}
		// 获取引擎状态，注入到所有页面模板数据中
		modelStatus, modelError, modelErrMsg := GetModelStatus()
		if r.Method == http.MethodGet {
			render(w, tmplScan, map[string]interface{}{
				"Username":         sess.Username,
				"HasPersonal":      userPerms["HasPersonal"],
				"HasUserMgmt":      userPerms["HasUserMgmt"],
				"HasLogPerm":       userPerms["HasLogPerm"],
				"ModelStatus":      modelStatus,
				"ModelError":       modelError,
				"ModelErrMsg":      modelErrMsg,
				"SandboxAvailable": sandbox.IsSandboxAvailable(),
			})
			return
		}
		if r.Method != http.MethodPost {
			sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
			return
		}
		if err := r.ParseMultipartForm(100 << 20); err != nil {
			sendJSON(w, http.StatusBadRequest, map[string]string{
				"error": "文件太大或解析失败",
			})
			return
		}
		files := r.MultipartForm.File["files"]
		if len(files) == 0 {
			sendJSON(w, http.StatusBadRequest, map[string]string{
				"error": "请上传至少一个文件",
			})
			return
		}
		// 原始名称取第一个文件名作为代表
		originalName := files[0].Filename
		if len(files) > 1 {
			originalName = fmt.Sprintf("%s 等 %d 个文件", originalName, len(files))
		}
		tmpDir, err := os.MkdirTemp("", "skill-scan-*")
		if err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "创建临时目录失败",
			})
			return
		}
		defer os.RemoveAll(tmpDir)
		// 保存所有上传的文件（支持文件夹内多文件）
		for _, fh := range files {
			if fh.Size == 0 {
				continue
			}
			if !isSafeFilename(fh.Filename) {
				sendJSON(w, http.StatusBadRequest, map[string]string{
					"error": "不支持的文件名",
				})
				return
			}
			// 保留相对路径结构（对于文件夹上传，浏览器会提供带路径的文件名）
			relPath := filepath.Clean(fh.Filename)
			destPath := filepath.Join(tmpDir, relPath)
			// 安全检查
			if !storage.IsPathSafe(tmpDir, relPath) {
				sendJSON(w, http.StatusBadRequest, map[string]string{
					"error": "文件路径不安全",
				})
				return
			}
			// 创建父目录
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				sendJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "创建目录失败",
				})
				return
			}
			src, err := fh.Open()
			if err != nil {
				sendJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "读取文件失败",
				})
				return
			}
			dst, err := os.Create(destPath)
			if err != nil {
				src.Close()
				sendJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "保存文件失败",
				})
				return
			}
			_, err = io.Copy(dst, src)
			src.Close()
			dst.Close()
			if err != nil {
				sendJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "写入文件失败",
				})
				return
			}
		}
		// 安全性校验
		if err := validateExtractedFiles(tmpDir); err != nil {
			sendJSON(w, http.StatusBadRequest, map[string]string{
				"error": err.Error(),
			})
			return
		}
		// 初始化扫描结果
		var findings []plugins.Finding
		var evalResult *evaluator.EvaluationResult
		// 读取表单中的技能描述和权限
		description := r.FormValue("description")
		permissionsStr := r.FormValue("permissions")
		permissions := []string{}
		if permissionsStr != "" {
			for _, p := range strings.Split(permissionsStr, ",") {
				if p = strings.TrimSpace(p); p != "" {
					permissions = append(permissions, p)
				}
			}
		}
		// 使用全局嵌入器（如果可用）
		if globalEmbedder != nil && embedderInitError == nil {
			cfg, err := config.Load("config/rules.yaml")
			if err != nil {
				log.Printf("加载规则配置失败，使用默认内嵌规则: %v", err)
				// 可降级使用原 Evaluator，此处简单处理
				cfg = getDefaultConfig() // 需实现一个兜底配置
			}
			var llmClient llm.Client
			// 使用当前用户的 LLM 配置
			user := store.GetUser(sess.Username)
			if user != nil {
				userLLM := store.GetUserLLMConfig(sess.Username)
				if userLLM != nil && userLLM.Enabled && userLLM.APIKey != "" {
					switch userLLM.Provider {
					case "deepseek":
						llmClient = llm.NewDeepSeekClient(userLLM.APIKey)
						log.Printf("用户 %s 启用了 DeepSeek LLM 分析", sess.Username)
					case "minimax":
						if userLLM.MiniMaxGroupID != "" {
							llmClient = llm.NewMiniMaxClient(userLLM.MiniMaxGroupID, userLLM.APIKey)
							log.Printf("用户 %s 启用了 MiniMax LLM 分析", sess.Username)
						}
					}
				}
			}
			eval := evaluator.NewEvaluator(globalEmbedder, llmClient, cfg)
			// 收集代码和依赖信息
			var files []evaluator.SourceFile
			var dependencies []evaluator.Dependency
			var codeAnalysis *analyzer.CodeAnalysisResult
			filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
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
					return nil // 跳过不支持的语言
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return nil
				}
				content := string(data)
				files = append(files, evaluator.SourceFile{
					Path:     path,
					Content:  content,
					Language: lang,
				})
				// 静态分析每个文件，累积结果（用于可能的降级展示）
				var fileAnalysis *analyzer.CodeAnalysisResult
				if lang == "go" {
					fileAnalysis = analyzer.AnalyzeGoCode(content, path)
				} else if lang == "javascript" || lang == "typescript" {
					fileAnalysis = analyzer.AnalyzeJavaScriptCode(content, path)
				}
				if fileAnalysis != nil {
					if codeAnalysis == nil {
						codeAnalysis = fileAnalysis
					} else {
						codeAnalysis.DangerousCalls = append(codeAnalysis.DangerousCalls, fileAnalysis.DangerousCalls...)
						codeAnalysis.HasHardcoded = codeAnalysis.HasHardcoded || fileAnalysis.HasHardcoded
					}
				}
				// 解析 go.mod
				if filepath.Base(path) == "go.mod" {
					deps, err := parseGoMod(content)
					if err == nil {
						dependencies = append(dependencies, deps...)
					}
				}
				// 解析 package.json
				if filepath.Base(path) == "package.json" {
					var pkg struct {
						Dependencies map[string]string `json:"dependencies"`
					}
					if json.Unmarshal(data, &pkg) == nil {
						for name, version := range pkg.Dependencies {
							dependencies = append(dependencies, evaluator.Dependency{
								Name:    name,
								Version: version,
							})
						}
					}
				}
				return nil
			})
			// 依赖去重（简单实现）
			depMap := make(map[string]evaluator.Dependency)
			for _, dep := range dependencies {
				key := dep.Name + "@" + dep.Version
				if _, exists := depMap[key]; !exists {
					depMap[key] = dep
				}
			}
			dependencies = make([]evaluator.Dependency, 0, len(depMap))
			for _, dep := range depMap {
				dependencies = append(dependencies, dep)
			}
			skill := &evaluator.Skill{
				Name:         originalName,
				Description:  description,
				Code:         "", // 不再使用单一字符串
				Files:        files,
				Dependencies: dependencies,
				Permissions:  permissions,
			}
			evalResult, err = eval.EvaluateWithCascade(context.Background(), skill)
			if err == nil {
				findings = convertResultToFindings(evalResult, cfg)
			} else {
				// 评估出错，回退到插件扫描
				findings = runPlugins(tmpDir)
			}
		} else {
			// 嵌入器不可用，直接使用插件
			findings = runPlugins(tmpDir)
		}

		// 新增：动态沙箱扫描
		// 检测沙箱是否可用，进行动态行为分析
		if sandbox.IsSandboxAvailable() {
			skillLang := sandbox.DetectLanguage(tmpDir)
			if skillLang != "" {
				log.Printf("检测到技能语言: %s，启动隔离沙箱进行动态行为扫描", skillLang)
				// 为沙箱设置独立超时（比内部默认超时稍长，避免竞争）
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
				} else {
					if sandbox.HasMaliciousIndicators("", logs.Logs) {
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
			} else {
				log.Printf("未识别到支持的技能语言，跳过动态沙箱扫描")
			}
		} else {
			log.Printf("Docker 沙箱不可用，跳过动态沙箱扫描")
		}

		// 生成报告
		reportFile := filepath.Join(tmpDir, "report.docx")
		gen := docx.NewGenerator()
		modelStatus, _, _ = GetModelStatus()
		llmEnabled := os.Getenv("DEEPSEEK_API_KEY") != "" // 简单判断
		score := 100.0
		if evalResult != nil {
			score = evalResult.Score
		}
		if err := gen.Generate(findings, score, modelStatus, llmEnabled, reportFile); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "生成报告失败",
			})
			return
		}
		reportID, err := storage.GenerateID()
		if err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "生成报告ID失败",
			})
			return
		}
		reportFileName := fmt.Sprintf("report_%s.docx", reportID)
		reportDest := filepath.Join(store.ReportsDir(), reportFileName)
		if err := copyFile(reportFile, reportDest); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "保存报告失败",
			})
			return
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
		user = store.GetUser(sess.Username)
		team := ""
		if user != nil {
			team = user.Team
		}
		rep := &models.Report{
			ID:           reportID,
			Username:     sess.Username,
			Team:         team,
			FileName:     originalName,
			FilePath:     reportFileName,
			CreatedAt:    time.Now().Unix(),
			FindingCount: len(findings),
			HighRisk:     high,
			MediumRisk:   medium,
			LowRisk:      low,
			NoRisk:       len(findings) == 0,
		}
		if err := store.AddReport(rep); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "保存报告记录失败",
			})
			return
		}
		sendJSON(w, http.StatusOK, map[string]interface{}{
			"success":       true,
			"report_id":     reportID,
			"finding_count": len(findings),
		})
	}
}

// -------- File handling helpers --------
func isSafeFilename(name string) bool {
	clean := filepath.Clean(name)
	return !strings.Contains(clean, "..") &&
		!strings.Contains(name, "\x00") &&
		clean != "" && clean != "."
}
func validateExtractedFiles(tmpDir string) error {
	var validationErrors []error
	walkErr := filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("failed to access path %s: %w", path, err))
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(tmpDir, path)
		if err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("directory traversal detected: invalid path %s, %w", path, err))
			return filepath.SkipDir
		}
		if strings.HasPrefix(relPath, "..") || strings.Contains(relPath, "/../") || !storage.IsPathSafe(tmpDir, relPath) {
			validationErrors = append(validationErrors, fmt.Errorf("directory traversal detected: malicious path %s", path))
			return filepath.SkipDir
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("failed to walk extracted directory: %w", walkErr)
	}
	if len(validationErrors) > 0 {
		return fmt.Errorf("file validation failed: %v", validationErrors)
	}
	return nil
}
func copyFile(src, dst string) error {
	srcF, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcF.Close()
	dstF, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstF.Close()
	_, err = io.Copy(dstF, srcF)
	return err
}
func runPlugins(scanPath string) []plugins.Finding {
	ctx := context.Background()
	allPlugins := []plugins.Plugin{
		plugins.NewSecretDetector(),
		plugins.NewDangerousCallDetector(),
	}
	var all []plugins.Finding
	for _, p := range allPlugins {
		findings, err := p.Execute(ctx, scanPath)
		if err != nil {
			continue
		}
		all = append(all, findings...)
	}
	return all
}
func parseGoMod(content string) ([]evaluator.Dependency, error) {
	f, err := modfile.Parse("go.mod", []byte(content), nil)
	if err != nil {
		return nil, err
	}
	var deps []evaluator.Dependency
	for _, r := range f.Require {
		deps = append(deps, evaluator.Dependency{
			Name:    r.Mod.Path,
			Version: r.Mod.Version,
		})
	}
	return deps, nil
}
func convertResultToFindings(result *evaluator.EvaluationResult, cfg *config.Config) []plugins.Finding {
	var findings []plugins.Finding
	// 1. 处理已有的 FindingDetails（这些已经带有精确位置）
	for _, detail := range result.FindingDetails {
		findings = append(findings, plugins.Finding{
			PluginName:  "SecurityEngine",
			RuleID:      detail.RuleID,
			Severity:    detail.Severity,
			Title:       detail.Title,
			Description: detail.Description,
			Location:    detail.Location,
			CodeSnippet: detail.CodeSnippet,
		})
	}
	// 2. 暂时移除不存在的 RejectReasons 逻辑，若需要可从其他字段（如 Score）判断
	return findings
}

// getDefaultConfig 兜底的默认配置
func getDefaultConfig() *config.Config {
	// 兜底：返回空配置，后续流程会使用默认插件扫描
	return &config.Config{}
}

// truncateString 截断字符串到指定长度，超出部分添加 "..."
func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
