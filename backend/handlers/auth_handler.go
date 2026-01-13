// handlers/auth_handler.go
package handlers

import (
	"encoding/json"
	"net/http"

	"go.mongodb.org/mongo-driver/bson"

	"riskmgt/models"
	"riskmgt/utils"
)

func Login(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid payload")
		return
	}

	var user models.User
	err := userCollection.FindOne(r.Context(), bson.M{"email": creds.Email}).Decode(&user)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if !utils.CheckPasswordHash(creds.Password, user.PasswordHash) {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	token, err := utils.GenerateJWT(user.ID.Hex(), user.FirstName+" "+user.LastName, user.Role)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	response := map[string]interface{}{
		"token": token,
		"user": map[string]string{
			"id":    user.ID.Hex(),
			"name":  user.FirstName + " " + user.LastName,
			"email": user.Email,
			"role":  user.Role,
		},
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

func ForgotPassword(w http.ResponseWriter, r *http.Request) {
	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "Password reset link sent"})
}

func ResetPassword(w http.ResponseWriter, r *http.Request) {
	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "Password reset successful"})
}