// models/approval.go
package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Approval struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	OrganizationID primitive.ObjectID `bson:"organizationId" json:"organizationId"`
	EntityType     string             `bson:"entityType" json:"entityType"` // e.g. "risk", "action", "delete-request"
	EntityID       primitive.ObjectID `bson:"entityId" json:"entityId"`
	RequestedBy    primitive.ObjectID `bson:"requestedBy" json:"requestedBy"`
	ApproverID     primitive.ObjectID `bson:"approverId" json:"approverId"`
	Status         string             `bson:"status" json:"status"` // e.g. "pending", "approved", "rejected"
	Comment        string             `bson:"comment,omitempty" json:"comment,omitempty"`
	CreatedAt      time.Time          `bson:"createdAt" json:"createdAt"`
	UpdatedAt      time.Time          `bson:"updatedAt" json:"updatedAt"`
}