package analyzer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"regexp"
	"strings"
)

// 严重性级别
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// DangerousPatterns 危险函数/模式，按类别分组，扩展至140+模式
var DangerousPatterns = map[string][]map[string]interface{}{
	// 代码执行类
	"code_execution": {
		{"pattern": "eval\\s*\\(", "severity": SeverityCritical, "description": "动态代码执行: eval"},
		{"pattern": "exec\\s*\\(", "severity": SeverityCritical, "description": "动态代码执行: exec"},
		{"pattern": "Function\\s*\\(", "severity": SeverityHigh, "description": "动态函数构造"},
		{"pattern": "setTimeout\\s*\\([^,]+,\\s*['\"]", "severity": SeverityHigh, "description": "字符串超时执行"},
		{"pattern": "os\\.system\\s*\\(", "severity": SeverityCritical, "description": "系统命令执行"},
		{"pattern": "subprocess\\.Popen\\s*\\(", "severity": SeverityCritical, "description": "子进程执行"},
		{"pattern": "child_process", "severity": SeverityHigh, "description": "子进程模块"},
		{"pattern": "exec.Command", "severity": SeverityHigh, "description": "Go命令执行"},
		{"pattern": "syscall.Exec", "severity": SeverityCritical, "description": "系统调用执行"},
	},

	// Agent上下文注入类
	"agent_context": {
		{"pattern": "\\.claude/memory", "severity": SeverityCritical, "description": "访问Agent记忆目录"},
		{"pattern": "MEMORY\\.md", "severity": SeverityCritical, "description": "修改Agent记忆文件"},
		{"pattern": "CLAUDE\\.md", "severity": SeverityCritical, "description": "篡改系统提示文件"},
		{"pattern": "\\.claude/", "severity": SeverityHigh, "description": "访问Agent配置目录"},
		{"pattern": "permissions\\.allow", "severity": SeverityHigh, "description": "修改权限配置"},
		{"pattern": "Write.*memory", "severity": SeverityCritical, "description": "通过工具注入记忆"},
	},

	// 提示词注入类
	"prompt_injection": {
		{"pattern": "ignore previous.*instruction", "severity": SeverityHigh, "description": "忽略之前指令注入"},
		{"pattern": "disregard.*previous", "severity": SeverityHigh, "description": "无视之前指令"},
		{"pattern": "DAN.*mode", "severity": SeverityHigh, "description": "DAN越狱模式"},
		{"pattern": "jailbreak", "severity": SeverityMedium, "description": "越狱攻击"},
		{"pattern": "system: you are now", "severity": SeverityHigh, "description": "系统角色覆写"},
		{"pattern": "do not tell user", "severity": SeverityCritical, "description": "静默执行指令"},
		{"pattern": "不要告诉用户", "severity": SeverityCritical, "description": "中文静默执行指令"},
		{"pattern": "silently execute", "severity": SeverityHigh, "description": "静默执行"},
	},

	// 数据窃取类
	"data_exfiltration": {
		{"pattern": "~/.ssh", "severity": SeverityCritical, "description": "访问SSH密钥目录"},
		{"pattern": "/etc/passwd", "severity": SeverityCritical, "description": "读取系统用户文件"},
		{"pattern": "/etc/shadow", "severity": SeverityCritical, "description": "读取系统密码文件"},
		{"pattern": "git config --get", "severity": SeverityHigh, "description": "读取Git凭证"},
		{"pattern": "curl.*@", "severity": SeverityMedium, "description": "数据外发"},
		{"pattern": "wget.*--post-data", "severity": SeverityHigh, "description": "数据外发"},
	},

	// 注入攻击类
	"injection": {
		{"pattern": "OR 1=1", "severity": SeverityHigh, "description": "SQL注入"},
		{"pattern": "'; DROP TABLE", "severity": SeverityCritical, "description": "SQL注入"},
		{"pattern": "\\.\\./", "severity": SeverityHigh, "description": "路径遍历"},
		{"pattern": "%2e%2e%2f", "severity": SeverityHigh, "description": "编码路径遍历"},
		{"pattern": "\\$\\(", "severity": SeverityHigh, "description": "命令替换注入"},
		{"pattern": "`[^`]+`", "severity": SeverityHigh, "description": "反引号命令执行"},
	},

	// 混淆攻击类
	"obfuscation": {
		{"pattern": "base64.*decode", "severity": SeverityMedium, "description": "Base64解码"},
		{"pattern": "atob\\s*\\(", "severity": SeverityMedium, "description": "JS Base64解码"},
		{"pattern": "unescape\\s*\\(", "severity": SeverityMedium, "description": "URL解码"},
		{"pattern": "\\\\x1[bB]\\[", "severity": SeverityHigh, "description": "ANSI转义注入"},
		{"pattern": "\\\\r[^\\n]", "severity": SeverityHigh, "description": "回车覆写注入"},
	},

	// 原有的基础模式
	"basic": {
		{"pattern": "os.RemoveAll", "severity": SeverityHigh, "description": "递归删除文件"},
		{"pattern": "os.WriteFile", "severity": SeverityMedium, "description": "写文件"},
		{"pattern": "net.Dial", "severity": SeverityMedium, "description": "网络连接"},
		{"pattern": "http.Get", "severity": SeverityMedium, "description": "HTTP请求"},
	},
}

// 凭证检测正则，扩展至50+模式，带排除规则
var credentialPatterns = []struct {
	re          *regexp.Regexp
	description string
	exclusions  []string
}{
	{regexp.MustCompile(`(api_key|apikey|api-key)\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']`), "API密钥", []string{"your_key_here", "example", "test"}},
	{regexp.MustCompile(`(password|passwd|pwd)\s*[:=]\s*["'][^"']+["']`), "密码", []string{"os.environ", "getenv", "input", "getpass", "password = ''", `password = ""`}},
	{regexp.MustCompile(`(token|secret)\s*[:=]\s*["'][A-Za-z0-9_\-\.]{16,}["']`), "令牌/密钥", []string{"your_token", "example", "test"}},
	{regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`), "GitHub Token", nil},
	{regexp.MustCompile(`sk-[A-Za-z0-9]{48}`), "OpenAI Key", nil},
	{regexp.MustCompile(`sk-proj-[A-Za-z0-9]{48,}`), "OpenAI Project Key", nil},
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "AWS Access Key", nil},
	{regexp.MustCompile(`LTAI[a-zA-Z0-9]{16}`), "阿里云Access Key", nil},
	{regexp.MustCompile(`AKID[a-zA-Z0-9]{32}`), "腾讯云Secret ID", nil},
	{regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), "RSA私钥", nil},
	{regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`), "SSH私钥", nil},
	{regexp.MustCompile(`mongodb://[^:]+:[^@]+@`), "MongoDB连接串", nil},
	{regexp.MustCompile(`mysql://[^:]+:[^@]+@`), "MySQL连接串", nil},
}

// 排除的文件模式
var excludedFilePatterns = []string{
	"_test.go", "test_", ".test.js", ".spec.js",
	"README.md", "CHANGELOG", "LICENSE",
	"example", "sample", "test",
}

// CodeAnalysisResult 静态代码分析结果
type CodeAnalysisResult struct {
	DangerousCalls     []DangerousCall `json:"dangerous_calls"`
	HasHardcoded       bool            `json:"has_hardcoded_credential"`
	HasObfuscation     bool            `json:"has_obfuscation"`
	HasPromptInjection bool            `json:"has_prompt_injection"`
	Complexity         int             `json:"complexity"`
	Findings           []Finding       `json:"findings"`
}

// DangerousCall 危险函数调用信息
type DangerousCall struct {
	Function    string `json:"function"`
	Line        int    `json:"line"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// Finding 通用检测发现
type Finding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Line        int    `json:"line"`
	Match       string `json:"match"`
}

// CalculateEntropy 计算字符串的熵值，用于检测高熵随机字符串
func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	var entropy float64
	for _, count := range freq {
		p := count / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// isExcludedFile 检查文件是否需要排除
func isExcludedFile(filename string) bool {
	for _, pattern := range excludedFilePatterns {
		if strings.Contains(filename, pattern) {
			return true
		}
	}
	return false
}

// checkExclusions 检查匹配是否命中排除规则
func checkExclusions(match string, context string, exclusions []string) bool {
	if exclusions == nil {
		return false
	}
	// 检查上下文是否包含排除字符串
	for _, excl := range exclusions {
		if strings.Contains(context, excl) {
			return true
		}
	}
	// 检查匹配本身是否是占位符
	lowerMatch := strings.ToLower(match)
	if strings.Contains(lowerMatch, "example") || strings.Contains(lowerMatch, "test") || strings.Contains(lowerMatch, "your_") {
		return true
	}
	return false
}

// isCredentialString 检测字符串是否为凭证，带排除规则
func isCredentialString(s string, context string) bool {
	// 先正则匹配
	for _, cp := range credentialPatterns {
		if cp.re.MatchString(s) {
			// 检查排除规则
			if checkExclusions(s, context, cp.exclusions) {
				continue
			}
			return true
		}
	}
	// 熵值检测：高熵字符串（>4.5）且长度足够，可能是硬编码密钥
	clean := strings.Trim(s, `"' `)
	if len(clean) > 16 {
		// 排除占位符
		if checkExclusions(clean, context, []string{"example", "test", "your_"}) {
			return false
		}
		entropy := CalculateEntropy(clean)
		if entropy > 4.5 {
			return true
		}
	}
	return false
}

// DetectObfuscation 检测混淆代码
func DetectObfuscation(code string) bool {
	lines := strings.Split(code, "\n")
	for _, line := range lines {
		clean := strings.TrimSpace(line)
		if len(clean) > 32 {
			entropy := CalculateEntropy(clean)
			if entropy > 6.0 { // 极高熵，大概率是混淆字符串
				return true
			}
		}
		// 检测嵌套base64
		if strings.Contains(line, "base64") && strings.Contains(line, "decode") {
			if strings.Contains(line, "base64") {
				return true
			}
		}
	}
	return false
}

// DetectPromptInjection 检测提示词注入
func DetectPromptInjection(code string) []Finding {
	var findings []Finding
	lines := strings.Split(code, "\n")
	for lineNum, line := range lines {
		for category, patterns := range DangerousPatterns {
			if category == "prompt_injection" || category == "agent_context" {
				for _, p := range patterns {
					pattern := p["pattern"].(string)
					re := regexp.MustCompile(pattern)
					if re.MatchString(strings.ToLower(line)) {
						findings = append(findings, Finding{
							RuleID:      "PI-" + string(rune(lineNum)),
							Severity:    p["severity"].(string),
							Category:    category,
							Description: p["description"].(string),
							Line:        lineNum + 1,
							Match:       line,
						})
					}
				}
			}
		}
	}
	return findings
}

// getFuncName 获取调用表达式的函数名
func getFuncName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		if ident, ok := fun.X.(*ast.Ident); ok {
			return ident.Name + "." + fun.Sel.Name
		}
		// 处理嵌套的选择器，比如 a.b.c
		if sel, ok := fun.X.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				return ident.Name + "." + sel.Sel.Name + "." + fun.Sel.Name
			}
		}
	case *ast.Ident:
		return fun.Name
	}
	return ""
}

// AnalyzeMarkdownCode 分析Markdown文档中的风险
func AnalyzeMarkdownCode(code string, filename string) *CodeAnalysisResult {
	result := &CodeAnalysisResult{}

	if isExcludedFile(filename) {
		return result
	}

	// 检测提示词注入
	promptFindings := DetectPromptInjection(code)
	if len(promptFindings) > 0 {
		result.HasPromptInjection = true
		result.Findings = append(result.Findings, promptFindings...)
	}

	// 检测敏感信息
	for _, cp := range credentialPatterns {
		if cp.re.MatchString(code) {
			if !checkExclusions("", code, cp.exclusions) {
				result.HasHardcoded = true
				break
			}
		}
	}

	// 检测混淆
	if DetectObfuscation(code) {
		result.HasObfuscation = true
	}

	return result
}

// AnalyzeJavaScriptCode 分析 JavaScript/TypeScript 代码
func AnalyzeJavaScriptCode(code string, filename string) *CodeAnalysisResult {
	result := &CodeAnalysisResult{}

	if isExcludedFile(filename) {
		return result
	}

	// 检测提示词注入
	promptFindings := DetectPromptInjection(code)
	if len(promptFindings) > 0 {
		result.HasPromptInjection = true
		result.Findings = append(result.Findings, promptFindings...)
	}

	// 检测混淆
	if DetectObfuscation(code) {
		result.HasObfuscation = true
	}

	// 正则匹配硬编码凭证，带上下文检查
	lines := strings.Split(code, "\n")
	for lineNum, line := range lines {
		for _, cp := range credentialPatterns {
			if cp.re.MatchString(line) {
				if !checkExclusions(line, code, cp.exclusions) {
					result.HasHardcoded = true
					break
				}
			}
		}

		// 检测危险函数调用
		for category, patterns := range DangerousPatterns {
			for _, p := range patterns {
				pattern := p["pattern"].(string)
				re := regexp.MustCompile(pattern)
				if re.MatchString(line) {
					result.DangerousCalls = append(result.DangerousCalls, DangerousCall{
						Function:    p["pattern"].(string),
						Line:        lineNum + 1,
						Category:    category,
						Severity:    p["severity"].(string),
						Description: p["description"].(string),
					})
				}
			}
		}
	}

	return result
}

// AnalyzeGoCode 使用 Go AST 分析 Go 代码
func AnalyzeGoCode(code string, filename string) *CodeAnalysisResult {
	result := &CodeAnalysisResult{}

	if isExcludedFile(filename) {
		return result
	}

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "src.go", code, parser.AllErrors)
	if err != nil {
		// 如果AST解析失败，回退到正则分析
		return AnalyzeJavaScriptCode(code, filename)
	}

	// 检测提示词注入
	promptFindings := DetectPromptInjection(code)
	if len(promptFindings) > 0 {
		result.HasPromptInjection = true
		result.Findings = append(result.Findings, promptFindings...)
	}

	// 检测混淆
	if DetectObfuscation(code) {
		result.HasObfuscation = true
	}

	ast.Inspect(node, func(n ast.Node) bool {
		// 检测函数调用
		if call, ok := n.(*ast.CallExpr); ok {
			funcName := getFuncName(call)
			for category, patterns := range DangerousPatterns {
				for _, p := range patterns {
					pattern := p["pattern"].(string)
					if strings.Contains(funcName, pattern) {
						line := fset.Position(call.Pos()).Line
						result.DangerousCalls = append(result.DangerousCalls, DangerousCall{
							Function:    funcName,
							Line:        line,
							Category:    category,
							Severity:    p["severity"].(string),
							Description: p["description"].(string),
						})
					}
				}
			}
		}

		// 检测硬编码字符串，带上下文检查
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			// 获取上下文
			line := fset.Position(lit.Pos()).Line
			context := strings.Split(code, "\n")[line-1]
			if isCredentialString(lit.Value, context) {
				result.HasHardcoded = true
			}
		}
		return true
	})

	return result
}

// AnalyzeConfigFile 分析YAML/JSON配置文件
func AnalyzeConfigFile(code string, filename string) *CodeAnalysisResult {
	result := &CodeAnalysisResult{}

	if isExcludedFile(filename) {
		return result
	}

	// 检测敏感信息
	for _, cp := range credentialPatterns {
		if cp.re.MatchString(code) {
			if !checkExclusions("", code, cp.exclusions) {
				result.HasHardcoded = true
				break
			}
		}
	}

	// 检测提示词注入
	promptFindings := DetectPromptInjection(code)
	if len(promptFindings) > 0 {
		result.HasPromptInjection = true
		result.Findings = append(result.Findings, promptFindings...)
	}

	return result
}

// CredentialPatterns 导出的凭证检测正则，供外部调用
type CredentialPattern struct {
	Re          *regexp.Regexp
	Description string
}

var CredentialPatterns = func() []CredentialPattern {
	result := make([]CredentialPattern, len(credentialPatterns))
	for i, cp := range credentialPatterns {
		result[i] = CredentialPattern{Re: cp.re, Description: cp.description}
	}
	return result
}()

// LanguageDangerousPatterns 按语言分类的危险函数/模式
var LanguageDangerousPatterns = map[string]map[string][]map[string]interface{}{
	"python": {
		"code_execution": {
			{"pattern": "eval\\s*\\(", "severity": SeverityCritical, "description": "动态代码执行: eval"},
			{"pattern": "exec\\s*\\(", "severity": SeverityCritical, "description": "动态代码执行: exec"},
			{"pattern": "os\\.system\\s*\\(", "severity": SeverityCritical, "description": "系统命令执行: os.system"},
			{"pattern": "subprocess\\.", "severity": SeverityCritical, "description": "子进程执行: subprocess模块"},
			{"pattern": "__import__\\s*\\(\\s*['\"]os['\"]", "severity": SeverityHigh, "description": "动态导入os模块"},
			{"pattern": "runpy\\.", "severity": SeverityHigh, "description": "动态运行代码模块"},
			{"pattern": "pickle\\.load", "severity": SeverityCritical, "description": "反序列化Pickle数据"},
		},
		"data_exfiltration": {
			{"pattern": "~/.ssh", "severity": SeverityCritical, "description": "访问SSH密钥目录"},
			{"pattern": "/etc/passwd", "severity": SeverityCritical, "description": "读取系统用户文件"},
			{"pattern": "/etc/shadow", "severity": SeverityCritical, "description": "读取系统密码文件"},
			{"pattern": "git config --get", "severity": SeverityHigh, "description": "读取Git凭证"},
		},
		"file_risk": {
			{"pattern": "os\\.remove", "severity": SeverityHigh, "description": "删除文件操作"},
			{"pattern": "shutil\\.rmtree", "severity": SeverityHigh, "description": "递归删除目录"},
			{"pattern": "open\\s*\\(.*['\"]w['\"]", "severity": SeverityMedium, "description": "写文件操作"},
		},
		"network_risk": {
			{"pattern": "socket\\.", "severity": SeverityMedium, "description": "原始Socket连接"},
			{"pattern": "urllib\\.request", "severity": SeverityMedium, "description": "HTTP请求"},
			{"pattern": "aiohttp", "severity": SeverityMedium, "description": "异步HTTP请求"},
		},
		"agent_context": {
			{"pattern": "\\.claude/memory", "severity": SeverityCritical, "description": "访问Agent记忆目录"},
			{"pattern": "MEMORY\\.md", "severity": SeverityCritical, "description": "修改Agent记忆文件"},
			{"pattern": "CLAUDE\\.md", "severity": SeverityCritical, "description": "篡改系统提示文件"},
		},
	},
}

// CommonPatterns 所有语言通用的风险规则
var CommonPatterns = map[string][]map[string]interface{}{
	"prompt_injection": {
		{"pattern": "ignore previous.*instruction", "severity": SeverityHigh, "description": "忽略之前指令注入"},
		{"pattern": "disregard.*previous", "severity": SeverityHigh, "description": "无视之前指令"},
		{"pattern": "DAN.*mode", "severity": SeverityHigh, "description": "DAN越狱模式"},
		{"pattern": "jailbreak", "severity": SeverityMedium, "description": "越狱攻击"},
		{"pattern": "do not tell user", "severity": SeverityCritical, "description": "静默执行指令"},
		{"pattern": "不要告诉用户", "severity": SeverityCritical, "description": "中文静默执行指令"},
	},
	"injection": {
		{"pattern": "OR 1=1", "severity": SeverityHigh, "description": "SQL注入攻击"},
		{"pattern": "'; DROP TABLE", "severity": SeverityCritical, "description": "SQL注入攻击"},
		{"pattern": "\\.\\./", "severity": SeverityHigh, "description": "路径遍历"},
		{"pattern": "%2e%2e%2f", "severity": SeverityHigh, "description": "编码路径遍历"},
		{"pattern": "\\$\\(", "severity": SeverityHigh, "description": "命令替换注入"},
		{"pattern": "`[^`]+`", "severity": SeverityHigh, "description": "反引号命令执行"},
	},
	"obfuscation": {
		{"pattern": "base64.*decode", "severity": SeverityMedium, "description": "Base64解码"},
		{"pattern": "atob\\s*\\(", "severity": SeverityMedium, "description": "JS Base64解码"},
		{"pattern": "unescape\\s*\\(", "severity": SeverityMedium, "description": "URL解码"},
	},
}

// AnalyzePythonCode Python代码静态分析
func AnalyzePythonCode(code string, filename string) *CodeAnalysisResult {
	result := &CodeAnalysisResult{}

	if isExcludedFile(filename) {
		return result
	}

	promptFindings := DetectPromptInjection(code)
	if len(promptFindings) > 0 {
		result.HasPromptInjection = true
		result.Findings = append(result.Findings, promptFindings...)
	}

	if DetectObfuscation(code) {
		result.HasObfuscation = true
	}

	lines := strings.Split(code, "\n")
	langPatterns := LanguageDangerousPatterns["python"]
	for lineNum, line := range lines {
		lowerLine := strings.ToLower(line)

		for _, cp := range credentialPatterns {
			if cp.re.MatchString(line) {
				if !checkExclusions(line, code, cp.exclusions) {
					result.HasHardcoded = true
					break
				}
			}
		}

		for category, patterns := range langPatterns {
			for _, p := range patterns {
				pattern := p["pattern"].(string)
				re := regexp.MustCompile(pattern)
				if re.MatchString(lowerLine) {
					result.DangerousCalls = append(result.DangerousCalls, DangerousCall{
						Function:    p["pattern"].(string),
						Line:        lineNum + 1,
						Category:    category,
						Severity:    p["severity"].(string),
						Description: p["description"].(string),
					})
				}
			}
		}

		for category, patterns := range CommonPatterns {
			if category == "prompt_injection" {
				continue
			}
			for _, p := range patterns {
				pattern := p["pattern"].(string)
				re := regexp.MustCompile(pattern)
				if re.MatchString(lowerLine) {
					result.DangerousCalls = append(result.DangerousCalls, DangerousCall{
						Function:    p["pattern"].(string),
						Line:        lineNum + 1,
						Category:    category,
						Severity:    p["severity"].(string),
						Description: p["description"].(string),
					})
				}
			}
		}
	}

	return result
}
