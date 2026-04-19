package plugins

import (
"context"
"errors"
"go/ast"
"go/parser"
"go/token"
"io/fs"
"os"
"path/filepath"
"regexp"
)

// DangerousCallDetector scans Go/Python/JavaScript source files for dangerous function calls
// such as exec, eval, and os.Command that may indicate command injection risks.
type DangerousCallDetector struct{}

// NewDangerousCallDetector returns a new DangerousCallDetector.
func NewDangerousCallDetector() *DangerousCallDetector {
return &DangerousCallDetector{}
}

// Name implements Plugin.
func (p *DangerousCallDetector) Name() string {
return "DangerousCallDetector"
}

// Execute implements Plugin.
func (p *DangerousCallDetector) Execute(ctx context.Context, scanPath string) ([]Finding, error) {
var findings []Finding
// 多语言危险函数正则匹配规则
dangerousPatterns := []*regexp.Regexp{
regexp.MustCompile(`os\.system`),
regexp.MustCompile(`subprocess\.`),
regexp.MustCompile(`exec\.Command`),
regexp.MustCompile(`child_process`),
regexp.MustCompile(`eval\(`),
regexp.MustCompile(`exec\(`),
regexp.MustCompile(`__import__\('os'\)`),
}

err := filepath.Walk(scanPath, func(path string, info fs.FileInfo, err error) error {
if err != nil || info.IsDir() {
return nil
}

ext := filepath.Ext(path)
// 处理 Go 语言：原有的 AST 检测
if ext == ".go" {
fset := token.NewFileSet()
node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
if err != nil {
return nil
}

ast.Inspect(node, func(n ast.Node) bool {
call, ok := n.(*ast.CallExpr)
if !ok {
return true
}

sel, ok := call.Fun.(*ast.SelectorExpr)
if !ok {
return true
}

funcName := sel.Sel.Name
if !isDangerousFunc(funcName) {
return true
}

findings = append(findings, Finding{
PluginName:  p.Name(),
RuleID:      "DAN-001",
Severity:    "高风险",
Title:       "调用危险函数",
Description: "检测到 Go 危险函数 " + funcName + " 调用，可能导致命令执行",
Location:    path,
})

return true
})
return nil
}

// 处理 Python/JavaScript/TypeScript：正则匹配危险函数
if ext == ".py" || ext == ".js" || ext == ".ts" {
data, err := os.ReadFile(path)
if err != nil {
return nil
}
content := string(data)
// 检查所有危险模式
for _, re := range dangerousPatterns {
if re.MatchString(content) {
findings = append(findings, Finding{
PluginName:  p.Name(),
RuleID:      "DAN-002",
Severity:    "高风险",
Title:       "调用危险函数",
Description: "检测到危险函数调用，可能导致命令执行风险",
Location:    path,
})
break // 每个文件只报一次
}
}
}

return nil
})

if err != nil && !errors.Is(err, context.Canceled) {
return findings, err
}

return findings, nil
}

func isDangerousFunc(name string) bool {
switch name {
case "exec", "System", "eval", "Command":
return true
default:
return false
}
}
