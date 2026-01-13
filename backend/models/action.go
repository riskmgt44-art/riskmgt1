// models/action.go
package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Action struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	OrganizationID primitive.ObjectID `bson:"organizationId" json:"organizationId"`
	RiskID         primitive.ObjectID `bson:"riskId" json:"riskId"`
	Title          string             `bson:"title" json:"title"`
	Description    string             `bson:"description" json:"description"`
	Status         string             `bson:"status" json:"status"` // e.g. "open", "in-progress", "completed", "overdue"
	DueDate        time.Time          `bson:"dueDate" json:"dueDate"`
	AssignedTo     primitive.ObjectID `bson:"assignedTo,omitempty" json:"assignedTo,omitempty"`
	CreatedAt      time.Time          `bson:"createdAt" json:"createdAt"`
	UpdatedAt      time.Time          `bson:"updatedAt" json:"updatedAt"`
}