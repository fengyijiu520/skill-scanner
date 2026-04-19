package models

import "time"

type ScanJobStatus string

const (
	ScanJobQueued  ScanJobStatus = "queued"
	ScanJobRunning ScanJobStatus = "running"
	ScanJobSuccess ScanJobStatus = "success"
	ScanJobFailed  ScanJobStatus = "failed"
)

// ScanJob represents an async scan task.
type ScanJob struct {
	ID           string        `json:"id"`
	Username     string        `json:"username"`
	Team         string        `json:"team"`
	OriginalName string        `json:"original_name"`
	Status       ScanJobStatus `json:"status"`
	Progress     int           `json:"progress"`
	Error        string        `json:"error,omitempty"`
	ReportID     string        `json:"report_id,omitempty"`
	CreatedAt    int64         `json:"created_at"`
	StartedAt    int64         `json:"started_at,omitempty"`
	FinishedAt   int64         `json:"finished_at,omitempty"`
	DurationMs   int64         `json:"duration_ms,omitempty"`
	UpdatedAt    int64         `json:"updated_at"`
}

func NewScanJob(id, username, team, originalName string) *ScanJob {
	now := time.Now().Unix()
	return &ScanJob{
		ID:           id,
		Username:     username,
		Team:         team,
		OriginalName: originalName,
		Status:       ScanJobQueued,
		Progress:     0,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}
