package docx

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"skill-scanner/internal/plugins"
)

// Generator produces .docx risk reports from plugin findings.
type Generator struct{}

// NewGenerator returns a new Generator.
func NewGenerator() *Generator {
	return &Generator{}
}

// Generate writes a .docx report to outputPath.
func (g *Generator) Generate(findings []plugins.Finding, score float64, modelInfo string, llmEnabled bool, outputPath string) error {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	addFile := func(name, content string) {
		w, _ := zw.Create(name)
		w.Write([]byte(content))
	}

	addFile("[Content_Types].xml", contentTypesXML)
	addFile("_rels/.rels", relsXML)
	addFile("word/_rels/document.xml.rels", docRelsXML)
	addFile("word/document.xml", g.buildDocument(findings, score, modelInfo, llmEnabled))
	zw.Close()

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = buf.WriteTo(f)
	return err
}

func (g *Generator) buildDocument(findings []plugins.Finding, score float64, modelInfo string, llmEnabled bool) string {
    var b strings.Builder

    // 计算实际风险类别数（分组后的组数）
    high, medium, low := partition(findings)
    groupedHigh := groupByRuleID(high)
    groupedMedium := groupByRuleID(medium)
    groupedLow := groupByRuleID(low)
    totalRiskCategories := len(groupedHigh) + len(groupedMedium) + len(groupedLow)

    b.WriteString(docHeader)
    b.WriteString(para("技能扫描风险报告", "36", "center", true))
    b.WriteString(para(fmt.Sprintf("生成时间: %s", time.Now().Format("2006-01-02 15:04:05")), "24", "center", false))

    // 综合安全评分
    scoreColor := "008000"
    if score < 60 {
        scoreColor = "FF0000"
    } else if score < 80 {
        scoreColor = "FFA500"
    }
    b.WriteString(para(fmt.Sprintf("综合安全评分: %.1f / 100", score), "28", "left", false))
    b.WriteString(fmt.Sprintf(
        `<w:p><w:pPr><w:sz w:val="28"/></w:pPr><w:r><w:rPr><w:b/><w:color w:val="%s"/><w:sz w:val="32"/></w:rPr><w:t>%.1f</w:t></w:r><w:r><w:rPr><w:sz w:val="28"/></w:rPr><w:t> 分</w:t></w:r></w:p>`,
        scoreColor, score))
    b.WriteString(blankPara())

    // 显示风险类别数
    b.WriteString(para(fmt.Sprintf("总计发现: %d 项风险类别", totalRiskCategories), "28", "left", false))
    b.WriteString(blankPara())

	if len(findings) == 0 {
		b.WriteString(heading("✅ 未发现风险", "28"))
		b.WriteString(para("扫描范围内未检测到敏感信息泄露或危险函数调用。", "24", "left", false))
	} else {
        if len(high) > 0 {
            b.WriteString(heading(fmt.Sprintf("🔴 高风险 (%d项)", len(groupedHigh)), "32"))
            for _, items := range groupedHigh {
                first := items[0]
                b.WriteString(ruleHeading(first.RuleID, first.Title, "FF0000", "32"))
                for _, item := range items {
                    b.WriteString(findingDetailPara(item))
                }
                b.WriteString(blankPara())
            }
        }

        if len(medium) > 0 {
            b.WriteString(heading(fmt.Sprintf("🟡 中风险 (%d项)", len(groupedMedium)), "28"))
            for _, items := range groupedMedium {
                first := items[0]
                b.WriteString(ruleHeading(first.RuleID, first.Title, "FFA500", "28"))
                for _, item := range items {
                    b.WriteString(findingDetailPara(item))
                }
                b.WriteString(blankPara())
            }
        }

        if len(low) > 0 {
            b.WriteString(heading(fmt.Sprintf("🟢 低风险 (%d项)", len(groupedLow)), "24"))
            for _, items := range groupedLow {
                first := items[0]
                b.WriteString(ruleHeading(first.RuleID, first.Title, "008000", "24"))
                for _, item := range items {
                    b.WriteString(findingDetailPara(item))
                }
                b.WriteString(blankPara())
            }
        }
    }

	b.WriteString(blankPara())
	b.WriteString(heading("检测引擎说明", "28"))

	engineDesc := "• 语义相似度检测: " + modelInfo + "\n"
	engineDesc += "• 恶意模式匹配: 正则检测危险命令、后门、数据外发等\n"
	engineDesc += "• 静态代码分析: Go / JavaScript / TypeScript 危险调用检测\n"
	engineDesc += "• 依赖漏洞分析: 基于依赖版本与已知漏洞库比对\n"
	if llmEnabled {
		engineDesc += "• LLM 深度分析: 已启用，进行代码意图一致性审查"
	} else {
		engineDesc += "• LLM 深度分析: 未启用（配置 API Key 后可开启）"
	}
	b.WriteString(para(engineDesc, "24", "left", false))

	b.WriteString(docFooter)

	return b.String()
}

func partition(findings []plugins.Finding) (high, medium, low []plugins.Finding) {
	for _, f := range findings {
		switch f.Severity {
		case "高风险":
			high = append(high, f)
		case "中风险":
			medium = append(medium, f)
		default:
			low = append(low, f)
		}
	}
	return
}

func para(text, size, align string, bold bool) string {
	alignAttr := map[string]string{
		"center": `<w:jc w:val="center"/>`,
		"right":  `<w:jc w:val="right"/>`,
	}[align]
	if alignAttr == "" {
		alignAttr = `<w:jc w:val="left"/>`
	}

	boldAttr := ""
	if bold {
		boldAttr = `<w:b/>`
	}

	// 转义 XML 特殊字符
	text = escapeXML(text)

	return fmt.Sprintf(
		`<w:p><w:pPr>%s<w:sz w:val="%s"/></w:pPr><w:r>%s<w:rPr><w:sz w:val="%s"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
		alignAttr, size, boldAttr, size, text,
	)
}

func heading(text, size string) string {
	text = escapeXML(text)
	return fmt.Sprintf(
		`<w:p><w:pPr><w:pStyle w:val="Heading2"/><w:sz w:val="%s"/></w:pPr><w:r><w:rPr><w:b/><w:sz w:val="%s"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
		size, size, text,
	)
}

func findingPara(f plugins.Finding, color string) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:sz w:val="28"/></w:pPr><w:r><w:rPr><w:b/><w:color w:val="%s"/><w:sz w:val="28"/></w:rPr><w:t xml:space="preserve">[%s] %s</w:t></w:r></w:p>`,
		color, f.RuleID, escapeXML(f.Title),
	))
	b.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:sz w:val="24"/><w:ind w:left="400"/></w:pPr><w:r><w:rPr><w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">描述: %s</w:t></w:r></w:p>`,
		escapeXML(f.Description),
	))
	b.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:sz w:val="24"/><w:ind w:left="400"/></w:pPr><w:r><w:rPr><w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">位置: %s</w:t></w:r></w:p>`,
		escapeXML(f.Location),
	))

	// 输出代码片段
	if f.CodeSnippet != "" {
		b.WriteString(codeBlockPara(f.CodeSnippet))
	}

	b.WriteString(blankPara())
	return b.String()
}

func blankPara() string {
	return `<w:p/>`
}

// codeBlockPara 生成一个带背景色的代码块段落（类似终端输出）
func codeBlockPara(code string) string {
	code = escapeXML(code)
	lines := strings.Split(code, "\n")
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(`<w:p>`)
		b.WriteString(`<w:pPr>`)
		b.WriteString(`<w:shd w:val="clear" w:color="auto" w:fill="F5F5F5"/>`)
		b.WriteString(`<w:spacing w:before="0" w:after="0"/>`)
		b.WriteString(`<w:ind w:left="400"/>`)
		b.WriteString(`</w:pPr>`)
		b.WriteString(`<w:r>`)
		b.WriteString(`<w:rPr>`)
		b.WriteString(`<w:rFonts w:ascii="Courier New" w:hAnsi="Courier New" w:cs="Courier New"/>`)
		b.WriteString(`<w:sz w:val="20"/>`)
		b.WriteString(`</w:rPr>`)
		b.WriteString(`<w:t xml:space="preserve">` + line + `</w:t>`)
		b.WriteString(`</w:r>`)
		b.WriteString(`</w:p>`)
	}
	return b.String()
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// XML templates.
const (
	contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`

	relsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

	docRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
</Relationships>`

	docHeader = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>`

	docFooter = `</w:body></w:document>`
)

// groupByRuleID 将 findings 按 RuleID 分组
func groupByRuleID(findings []plugins.Finding) map[string][]plugins.Finding {
    grouped := make(map[string][]plugins.Finding)
    for _, f := range findings {
        grouped[f.RuleID] = append(grouped[f.RuleID], f)
    }
    return grouped
}

// ruleHeading 生成规则的主标题
func ruleHeading(ruleID, title, color, size string) string {
    return fmt.Sprintf(
        `<w:p><w:pPr><w:sz w:val="%s"/></w:pPr><w:r><w:rPr><w:b/><w:color w:val="%s"/><w:sz w:val="%s"/></w:rPr><w:t xml:space="preserve">[%s] %s</w:t></w:r></w:p>`,
        size, color, size, escapeXML(ruleID), escapeXML(title),
    )
}

// findingDetailPara 输出单个发现的位置和代码片段（不含标题）
func findingDetailPara(f plugins.Finding) string {
    var b strings.Builder
    desc := f.Description
    if f.RuleID == "LLM-DETECT" {
        desc = "[AI分析] " + desc
    }
    b.WriteString(fmt.Sprintf(
        `<w:p><w:pPr><w:sz w:val="24"/><w:ind w:left="400"/></w:pPr><w:r><w:rPr><w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">描述: %s</w:t></w:r></w:p>`,
        escapeXML(desc),
    ))
    b.WriteString(fmt.Sprintf(
        `<w:p><w:pPr><w:sz w:val="24"/><w:ind w:left="400"/></w:pPr><w:r><w:rPr><w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">位置: %s</w:t></w:r></w:p>`,
        escapeXML(f.Location),
    ))
    if f.CodeSnippet != "" {
        b.WriteString(codeBlockPara(f.CodeSnippet))
    }
    return b.String()
}