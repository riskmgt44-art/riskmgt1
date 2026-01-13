// handlers/collections.go
package handlers

import (
	"go.mongodb.org/mongo-driver/mongo"

	"riskmgt/database"
)

var (
	orgCollection   *mongo.Collection
	userCollection  *mongo.Collection
	actionCollection *mongo.Collection
	// Add more collections here later (e.g. riskCollection, approvalCollection, auditLogCollection)
)

func InitCollections() {
	db := database.Client.Database("riskmgt")

	orgCollection = db.Collection("organizations")
	userCollection = db.Collection("users")
	actionCollection = db.Collection("actions")
	// riskCollection = db.Collection("risks")
	// approvalCollection = db.Collection("approvals")
	// auditLogCollection = db.Collection("audit_logs")
}