// middleware/auth.go
package middleware

import (
	"context"
	"net/http"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"riskmgt/database"
	"riskmgt/models"
	"riskmgt/utils"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			utils.RespondWithError(w, http.StatusUnauthorized, "Missing or invalid Authorization header")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := utils.ValidateJWT(tokenString)
		if err != nil {
			utils.RespondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		userID, err := primitive.ObjectIDFromHex(claims.UserID)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Invalid user ID")
			return
		}

		var user models.User
		err = database.Client.Database("riskmgt").Collection("users").FindOne(r.Context(), bson.M{"_id": userID}).Decode(&user)
		if err != nil {
			utils.RespondWithError(w, http.StatusUnauthorized, "User not found")
			return
		}

		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		ctx = context.WithValue(ctx, "userName", claims.Name)
		ctx = context.WithValue(ctx, "userRole", claims.Role)
		ctx = context.WithValue(ctx, "orgID", user.OrganizationID.Hex())

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := utils.ValidateJWT(tokenString)
			if err == nil {
				ctx := context.WithValue(r.Context(), "userID", claims.UserID)
				ctx = context.WithValue(ctx, "userName", claims.Name)
				ctx = context.WithValue(ctx, "userRole", claims.Role)
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}