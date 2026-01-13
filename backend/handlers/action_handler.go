// handlers/action_handler.go
package handlers

import (
	"log"
	"net/http"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"riskmgt/models"
	"riskmgt/utils"
)

func ListActions(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDHex == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Always return [] not null — this is the #1 cause of frontend "loading forever"
	var actions []models.Action

	cursor, err := actionCollection.Find(r.Context(), bson.M{"organizationId": orgID})
	if err != nil {
		// Collection might not exist yet — this is normal in MongoDB
		if err == mongo.ErrNoDocuments || err.Error() == "no such collection" {
			log.Printf("No actions collection or empty for org %s", orgIDHex)
		} else {
			log.Printf("Mongo Find error for actions: %v", err)
		}
		// Still return empty array — never error out on empty
		utils.RespondWithJSON(w, http.StatusOK, actions)
		return
	}
	defer cursor.Close(r.Context())

	if err = cursor.All(r.Context(), &actions); err != nil {
		log.Printf("Cursor decode error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode actions")
		return
	}

	log.Printf("Successfully returned %d actions for org %s", len(actions), orgIDHex)
	utils.RespondWithJSON(w, http.StatusOK, actions)
}