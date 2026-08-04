package main

import (
	"database/sql"
	"time"
)

const (
	statusActive   = "active"
	statusDisabled = "disabled"
	statusArchived = "archived"

	outcomeAllowed = "allowed"
	outcomeDenied  = "denied"
)

type identity struct {
	Email        string
	DisplayName  string
	Role         string
	IsAdmin      bool
	IsSuperAdmin bool
}

type userRecord struct {
	ID          int64
	Email       string
	DisplayName string
	Status      string
	FirstSeenAt sql.NullInt64
	LastSeenAt  sql.NullInt64
	LoginCount  int64
	IsAdmin     bool
	CreatedAt   int64
	UpdatedAt   int64
}

type userResponse struct {
	ID           int64   `json:"id"`
	Email        string  `json:"email"`
	DisplayName  string  `json:"displayName"`
	Status       string  `json:"status"`
	FirstSeenAt  *string `json:"firstSeenAt"`
	LastSeenAt   *string `json:"lastSeenAt"`
	LoginCount   int64   `json:"loginCount"`
	IsAdmin      bool    `json:"isAdmin"`
	IsSuperAdmin bool    `json:"isSuperAdmin"`
	CreatedAt    string  `json:"createdAt"`
	UpdatedAt    string  `json:"updatedAt"`
}

type overviewResponse struct {
	Authorized   int64 `json:"authorized"`
	Disabled     int64 `json:"disabled"`
	Online       int64 `json:"online"`
	DeniedRecent int64 `json:"deniedRecent"`
}

type accessEventResponse struct {
	ID          int64  `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Outcome     string `json:"outcome"`
	CreatedAt   string `json:"createdAt"`
}

type auditResponse struct {
	ID          int64  `json:"id"`
	ActorEmail  string `json:"actorEmail"`
	TargetEmail string `json:"targetEmail"`
	Action      string `json:"action"`
	Detail      string `json:"detail"`
	CreatedAt   string `json:"createdAt"`
}

type pagedResponse[T any] struct {
	Items    []T   `json:"items"`
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"pageSize"`
}

type meResponse struct {
	Email              string `json:"email"`
	DisplayName        string `json:"displayName"`
	Name               string `json:"name"`
	Role               string `json:"role"`
	IsAdmin            bool   `json:"isAdmin"`
	IsSuperAdmin       bool   `json:"isSuperAdmin"`
	CanManageAdmins    bool   `json:"canManageAdmins"`
	CSRFToken          string `json:"csrfToken"`
	AllowedEmailDomain string `json:"allowedEmailDomain"`
}

type addUsersRequest struct {
	Email  string   `json:"email"`
	Emails []string `json:"emails"`
}

type addUserResult struct {
	Email  string `json:"email"`
	Result string `json:"result"`
	Reason string `json:"reason,omitempty"`
}

type addUsersSummary struct {
	Added    int `json:"added"`
	Existing int `json:"existing"`
	Invalid  int `json:"invalid"`
}

type addUsersResponse struct {
	Summary addUsersSummary `json:"summary"`
	Results []addUserResult `json:"results"`
}

type mutateUserRequest struct {
	Action string `json:"action"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func userToResponse(user userRecord) userResponse {
	status := user.Status
	if status == statusActive {
		status = "authorized"
	}
	return userResponse{
		ID:          user.ID,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Status:      status,
		FirstSeenAt: unixToStringPtr(user.FirstSeenAt),
		LastSeenAt:  unixToStringPtr(user.LastSeenAt),
		LoginCount:  user.LoginCount,
		IsAdmin:     user.IsAdmin,
		CreatedAt:   formatUnix(user.CreatedAt),
		UpdatedAt:   formatUnix(user.UpdatedAt),
	}
}

func unixToStringPtr(value sql.NullInt64) *string {
	if !value.Valid {
		return nil
	}
	formatted := formatUnix(value.Int64)
	return &formatted
}

func formatUnix(value int64) string {
	return time.Unix(value, 0).UTC().Format(time.RFC3339)
}
