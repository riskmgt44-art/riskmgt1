// handlers/organization_handler.go
package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"riskmgt/models"
	"riskmgt/utils"
)

type createOrgPayload struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	Industry       string `json:"industry"`
	Size           string `json:"size,omitempty"`
	Country        string `json:"country"`
	Timezone       string `json:"timezone"`
	AdminFirstName string `json:"adminFirstName"`
	AdminLastName  string `json:"adminLastName"`
	AdminEmail     string `json:"adminEmail"`
	AdminJobTitle  string `json:"adminJobTitle"`
	AdminPassword  string `json:"adminPassword"`
	AdminPhone     string `json:"adminPhone,omitempty"`
}

func CreateOrganization(w http.ResponseWriter, r *http.Request) {
	var payload createOrgPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid payload")
		return
	}

	if payload.Name == "" || payload.Type == "" || payload.Industry == "" ||
		payload.Country == "" || payload.Timezone == "" || payload.AdminFirstName == "" ||
		payload.AdminLastName == "" || payload.AdminEmail == "" || payload.AdminJobTitle == "" ||
		payload.AdminPassword == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Missing required fields")
		return
	}

	org := models.Organization{
		ID:        primitive.NewObjectID(),
		Name:      payload.Name,
		Type:      payload.Type,
		Industry:  payload.Industry,
		Size:      payload.Size,
		Country:   payload.Country,
		Timezone:  payload.Timezone,
		CreatedAt: time.Now().UTC(),
	}

	_, err := orgCollection.InsertOne(r.Context(), org)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create organization")
		return
	}

	hash, err := utils.HashPassword(payload.AdminPassword)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Password processing failed")
		return
	}

	user := models.User{
		ID:             primitive.NewObjectID(),
		FirstName:      payload.AdminFirstName,
		LastName:       payload.AdminLastName,
		Email:          payload.AdminEmail,
		JobTitle:       payload.AdminJobTitle,
		Phone:          payload.AdminPhone,
		PasswordHash:   hash,
		Role:           "superadmin",
		OrganizationID: org.ID,
		CreatedAt:      time.Now().UTC(),
	}

	_, err = userCollection.InsertOne(r.Context(), user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create super admin")
		return
	}

	token, err := utils.GenerateJWT(user.ID.Hex(), user.FirstName+" "+user.LastName, user.Role)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate authentication token")
		return
	}

	response := map[string]interface{}{
		"message": "Organization and super admin created successfully",
		"token":   token,
		"user": map[string]string{
			"id":    user.ID.Hex(),
			"name":  user.FirstName + " " + user.LastName,
			"email": user.Email,
			"role":  user.Role,
		},
		"organization": map[string]string{
			"id":   org.ID.Hex(),
			"name": org.Name,
		},
	}

	utils.RespondWithJSON(w, http.StatusCreated, response)
}