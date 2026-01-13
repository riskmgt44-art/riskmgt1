// models/risk.go
package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Risk struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	OrganizationID primitive.ObjectID `bson:"organizationId" json:"organizationId"`
	Title          string             `bson:"title" json:"title"`
	Description    string             `bson:"description" json:"description"`
	Severity       string             `bson:"severity" json:"severity"` // e.g. "low", "medium", "high", "critical"
	Status         string             `bson:"status" json:"status"`     // e.g. "open", "mitigated", "accepted"
	Category       string             `bson:"category" json:"category,omitempty"`
	OwnerID        primitive.ObjectID `bson:"ownerId,omitempty" json:"ownerId,omitempty"`
	CreatedAt      time.Time          `bson:"createdAt" json:"createdAt"`
	UpdatedAt      time.Time          `bson:"updatedAt" json:"updatedAt"`
}