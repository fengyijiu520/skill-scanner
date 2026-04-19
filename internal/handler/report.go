package handler

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

type reportEntry struct {
	ID           string
	FileName     string
	Username     string
	CreatedAt    string
	FindingCount int
	HighRisk     int
	MediumRisk   int
	LowRisk      int
	NoRisk       bool
}

type reportsPageData struct {
	Username    string
	Reports     []reportEntry
	IsAdmin     bool
	HasPersonal bool
	HasUserMgmt bool
	HasLogPerm  bool
}

type reportFindingView struct {
	PluginName  string
	RuleID      string
	Severity    string
	Title       string
	Description string
	Location    string
	CodeSnippet string
}

type ruleCountView struct {
	RuleID string
	Count  int
}

type reportDetailData struct {
	Username         string
	Report           *models.Report
	CreatedAt        string
	Findings         []reportFindingView
	DeclaredCaps     []string
	ObservedCaps     []string
	MatchedCaps      []string
	OverreachCaps    []string
	UnderdeclareCaps []string
	CapabilityScore  float64
	BaseScore        float64
	BaseWeight       float64
	CapWeight        float64
	WhitelistByRule  []ruleCountView
	HasPersonal      bool
	HasUserMgmt      bool
	HasLogPerm       bool
	ModelStatus      string
	ModelError       bool
	ModelErrMsg      string
}

// listReports shows all reports accessible to the current user.
func listReports(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		user := store.GetUser(sess.Username)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		reports := store.ListReports(sess.Username)

		sort.Slice(reports, func(i, j int) bool {
			return reports[i].CreatedAt > reports[j].CreatedAt
		})

		var entries []reportEntry
		for _, rep := range reports {
			entries = append(entries, reportEntry{
				ID:           rep.ID,
				FileName:     rep.FileName,
				Username:     rep.Username,
				CreatedAt:    time.Unix(rep.CreatedAt, 0).Format("2006-01-02 15:04"),
				FindingCount: rep.FindingCount,
				HighRisk:     rep.HighRisk,
				MediumRisk:   rep.MediumRisk,
				LowRisk:      rep.LowRisk,
				NoRisk:       rep.NoRisk,
			})
		}

		modelStatus, modelError, modelErrMsg := GetModelStatus()
		render(w, tmplReports, map[string]interface{}{
			"Username":    sess.Username,
			"Reports":     entries,
			"IsAdmin":     user.Role == models.RoleAdmin,
			"HasPersonal": user.HasPermission(models.PermPersonalCenter),
			"HasUserMgmt": user.HasPermission(models.PermUserManagement),
			"HasLogPerm":  user.HasPermission(models.PermLoginLog),
			"ModelStatus": modelStatus,
			"ModelError":  modelError,
			"ModelErrMsg": modelErrMsg,
		})
	}
}

func reportDetail(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		reportID := strings.TrimPrefix(r.URL.Path, "/reports/")
		reportID = filepath.Base(reportID)
		if reportID == "" || reportID == "/" || reportID == "." {
			http.Redirect(w, r, "/reports", http.StatusFound)
			return
		}

		rep := store.GetReport(reportID)
		if rep == nil {
			http.Error(w, "报告不存在", http.StatusNotFound)
			return
		}
		if !store.CanAccessReport(sess.Username, reportID) {
			http.Error(w, "无权访问此报告", http.StatusForbidden)
			return
		}

		user := store.GetUser(sess.Username)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		findings := make([]reportFindingView, 0, len(rep.Findings))
		for _, f := range rep.Findings {
			findings = append(findings, reportFindingView{
				PluginName:  f.PluginName,
				RuleID:      f.RuleID,
				Severity:    f.Severity,
				Title:       f.Title,
				Description: f.Description,
				Location:    f.Location,
				CodeSnippet: f.CodeSnippet,
			})
		}

		modelStatus, modelError, modelErrMsg := GetModelStatus()
		data := reportDetailData{
			Username:    sess.Username,
			Report:      rep,
			CreatedAt:   time.Unix(rep.CreatedAt, 0).Format("2006-01-02 15:04"),
			Findings:    findings,
			HasPersonal: user.HasPermission(models.PermPersonalCenter),
			HasUserMgmt: user.HasPermission(models.PermUserManagement),
			HasLogPerm:  user.HasPermission(models.PermLoginLog),
			ModelStatus: modelStatus,
			ModelError:  modelError,
			ModelErrMsg: modelErrMsg,
			BaseScore:   rep.BaseScore,
			BaseWeight:  rep.BaseWeight,
			CapWeight:   rep.CapabilityWeight,
		}
		if rep.Capability != nil {
			data.DeclaredCaps = rep.Capability.Declared
			data.ObservedCaps = rep.Capability.Observed
			data.MatchedCaps = rep.Capability.Matched
			data.OverreachCaps = rep.Capability.Overreach
			data.UnderdeclareCaps = rep.Capability.Underdeclare
			data.CapabilityScore = rep.Capability.Score
		}
		if rep.CapabilityScore > 0 {
			data.CapabilityScore = rep.CapabilityScore
		}
		if len(rep.WhitelistByRule) > 0 {
			data.WhitelistByRule = make([]ruleCountView, 0, len(rep.WhitelistByRule))
			for ruleID, c := range rep.WhitelistByRule {
				data.WhitelistByRule = append(data.WhitelistByRule, ruleCountView{RuleID: ruleID, Count: c})
			}
			sort.Slice(data.WhitelistByRule, func(i, j int) bool {
				if data.WhitelistByRule[i].Count == data.WhitelistByRule[j].Count {
					return data.WhitelistByRule[i].RuleID < data.WhitelistByRule[j].RuleID
				}
				return data.WhitelistByRule[i].Count > data.WhitelistByRule[j].Count
			})
		}

		render(w, tmplReportDetail, data)
	}
}

// downloadReport serves a report .docx file after checking authorization.
func downloadReport(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		reportID := strings.TrimPrefix(r.URL.Path, "/reports/download/")
		reportID = filepath.Base(reportID)
		if reportID == "" || reportID == "/" {
			http.Error(w, "报告不存在", http.StatusNotFound)
			return
		}

		// ID must be a clean path segment — no traversal characters.
		if reportID != filepath.Clean(reportID) {
			http.Error(w, "无效的报告ID", http.StatusBadRequest)
			return
		}

		rep := store.GetReport(reportID)
		if rep == nil {
			http.Error(w, "报告不存在", http.StatusNotFound)
			return
		}

		// Authorization using team-aware access check.
		if !store.CanAccessReport(sess.Username, reportID) {
			http.Error(w, "无权访问此报告", http.StatusForbidden)
			return
		}

		filePath := filepath.Join(store.ReportsDir(), rep.FilePath)
		if !storage.IsPathSafe(store.ReportsDir(), rep.FilePath) {
			http.Error(w, "无效的报告路径", http.StatusBadRequest)
			return
		}

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			http.Error(w, "报告文件不存在", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Disposition", "attachment; filename=skill-scan-report.docx")
		w.Header().Set("Content-Type",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document")
		http.ServeFile(w, r, filePath)
	}
}
