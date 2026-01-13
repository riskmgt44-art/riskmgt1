// models/audit_log.go
package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AuditLog struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	OrganizationID primitive.ObjectID `bson:"organizationId" json:"organizationId"`
	UserID         primitive.ObjectID `bson:"userId" json:"userId"`
	Action         string             `bson:"action" json:"action"` // e.g. "create_risk", "update_user_role", "approve_action"
	EntityType     string             `bson:"entityType" json:"entityType"`
	EntityID       primitive.ObjectID `bson:"entityId,omitempty" json:"entityId,omitempty"`
	Details        bson.M             `bson:"details,omitempty" json:"details,omitempty"`
	CreatedAt      time.Time          `bson:"createdAt" json:"createdAt"`
}