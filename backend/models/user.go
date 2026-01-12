// models/user.go
package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	FirstName      string             `bson:"firstName" json:"firstName"`
	LastName       string             `bson:"lastName" json:"lastName"`
	Email          string             `bson:"email" json:"email"`
	JobTitle       string             `bson:"jobTitle" json:"jobTitle"`
	Phone          string             `bson:"phone,omitempty" json:"phone,omitempty"`
	PasswordHash   string             `bson:"passwordHash" json:"-"`
	Role           string             `bson:"role" json:"role"`
	OrganizationID primitive.ObjectID `bson:"organizationId" json:"organizationId"`
	CreatedAt      time.Time          `bson:"createdAt" json:"createdAt"`
}