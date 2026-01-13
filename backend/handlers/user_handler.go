// handlers/user_handler.go
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"riskmgt/models"
	"riskmgt/utils"
)

func CreateUsers(w http.ResponseWriter, r *http.Request) {
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

	role, ok := r.Context().Value("userRole").(string)
	if !ok || role != "superadmin" {
		utils.RespondWithError(w, http.StatusForbidden, "Only superadmin can create users")
		return
	}

	var users []models.User
	if err := json.NewDecoder(r.Body).Decode(&users); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid payload")
		return
	}

	var insertDocs []interface{}

	for i := range users {
		// Check for duplicate email within the organization
		count, err := userCollection.CountDocuments(
			r.Context(),
			bson.M{
				"email":          users[i].Email,
				"organizationId": orgID,
			},
		)
		if err != nil || count > 0 {
			continue // Skip duplicates
		}

		users[i].ID = primitive.NewObjectID()
		users[i].OrganizationID = orgID
		users[i].CreatedAt = time.Now().UTC()

		if users[i].PasswordHash == "" {
			tempPass := utils.GenerateRandomPassword(12)
			users[i].PasswordHash = tempPass

			// Placeholder: send invite email
			log.Printf(
				"Invite sent to %s with temporary password: %s",
				users[i].Email,
				tempPass,
			)
		}

		hash, err := utils.HashPassword(users[i].PasswordHash)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Password processing failed")
			return
		}
		users[i].PasswordHash = hash

		insertDocs = append(insertDocs, users[i])
	}

	if len(insertDocs) == 0 {
		utils.RespondWithJSON(
			w,
			http.StatusOK,
			map[string]string{"message": "No new users to create"},
		)
		return
	}

	if _, err := userCollection.InsertMany(r.Context(), insertDocs); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create users")
		return
	}

	utils.RespondWithJSON(
		w,
		http.StatusCreated,
		map[string]string{"message": "Users created successfully"},
	)
}

func ListUsers(w http.ResponseWriter, r *http.Request) {
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

	cursor, err := userCollection.Find(
		r.Context(),
		bson.M{"organizationId": orgID},
	)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch users")
		return
	}
	defer cursor.Close(r.Context())

	var users []models.User
	if err := cursor.All(r.Context(), &users); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Decode error")
		return
	}

	// Remove password hashes from response
	for i := range users {
		users[i].PasswordHash = ""
	}

	utils.RespondWithJSON(w, http.StatusOK, users)
}
