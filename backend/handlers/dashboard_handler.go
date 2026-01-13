// handlers/dashboard_handler.go
package handlers

import (
	"net/http"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"riskmgt/utils"
)

type ExecutiveOverview struct {
	TotalRisks         int64 `json:"totalRisks"`
	HighSeverityRisks  int64 `json:"highSeverityRisks"`
	OpenActions        int64 `json:"openActions"`
	OverdueActions     int64 `json:"overdueActions"`
	PendingApprovals   int64 `json:"pendingApprovals"`
	ActiveUsers        int64 `json:"activeUsers"`
	AuditEntries24h    int64 `json:"auditEntries24h"`
	RecentRoleChanges  int64 `json:"recentRoleChanges"`
	PolicyUpdates30d   int64 `json:"policyUpdates30d"`
}

func GetExecutiveOverview(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}
	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Invalid organization ID")
		return
	}

	// Real count: number of users in this organization
	activeUsers, err := userCollection.CountDocuments(r.Context(), bson.M{
		"organizationId": orgID,
	})
	if err != nil {
		activeUsers = 0 // fallback on error
	}

	overview := ExecutiveOverview{
		TotalRisks:         0,
		HighSeverityRisks:  0,
		OpenActions:        0,
		OverdueActions:     0,
		PendingApprovals:   0,
		ActiveUsers:        activeUsers,
		AuditEntries24h:    0,
		RecentRoleChanges:  0,
		PolicyUpdates30d:   0,
	}

	utils.RespondWithJSON(w, http.StatusOK, overview)
}