package handler

import (
	"net/http"

	"skill-scanner/internal/storage"
)

func Login(store *storage.Store) http.HandlerFunc            { return login(store) }
func ChangePassword(store *storage.Store) http.HandlerFunc   { return changePassword(store) }
func Logout() http.HandlerFunc                               { return logout() }
func Dashboard(store *storage.Store) http.HandlerFunc        { return dashboard(store) }
func Scan(store *storage.Store) http.HandlerFunc             { return scan(store) }
func CreateScanJob(store *storage.Store) http.HandlerFunc    { return createScanJob(store) }
func GetScanJobStatus(store *storage.Store) http.HandlerFunc { return getScanJobStatus(store) }
func ListReports(store *storage.Store) http.HandlerFunc      { return listReports(store) }
func ReportDetail(store *storage.Store) http.HandlerFunc     { return reportDetail(store) }
func DownloadReport(store *storage.Store) http.HandlerFunc   { return downloadReport(store) }
func Personal(store *storage.Store) http.HandlerFunc         { return personal(store) }
func AdminUsers(store *storage.Store) http.HandlerFunc       { return adminUsers(store) }

// LoginLog and RequireAuth are already exported from their respective files.
