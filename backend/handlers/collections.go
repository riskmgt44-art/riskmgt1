// handlers/collections.go
package handlers

import (
	"go.mongodb.org/mongo-driver/mongo"

	"riskmgt/database"
)

var (
	orgCollection  *mongo.Collection
	userCollection *mongo.Collection
)

func InitCollections() {
	orgCollection = database.Client.Database("riskmgt").Collection("organizations")
	userCollection = database.Client.Database("riskmgt").Collection("users")
}