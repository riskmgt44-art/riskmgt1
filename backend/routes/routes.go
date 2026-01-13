// routes/routes.go
package routes

import (
	"github.com/gorilla/mux"
	"riskmgt/handlers"
	"riskmgt/middleware"
)

func RegisterRoutes(router *mux.Router) {
	// Public routes
	public := router.PathPrefix("/api/auth").Subrouter()
	public.Use(middleware.OptionalAuth)
	public.HandleFunc("/login", handlers.Login).Methods("POST", "OPTIONS")
	public.HandleFunc("/forgot", handlers.ForgotPassword).Methods("POST", "OPTIONS")
	public.HandleFunc("/reset", handlers.ResetPassword).Methods("POST", "OPTIONS")

	router.HandleFunc("/api/organizations", handlers.CreateOrganization).Methods("POST", "OPTIONS")

	// Protected API routes
	api := router.PathPrefix("/api").Subrouter()
	api.Use(middleware.AuthMiddleware)

	// Users
	api.HandleFunc("/users", handlers.ListUsers).Methods("GET", "OPTIONS")
	api.HandleFunc("/users", handlers.CreateUsers).Methods("POST", "OPTIONS")

	// Dashboard
	api.HandleFunc("/dashboard/executive", handlers.GetExecutiveOverview).Methods("GET", "OPTIONS")

	// Actions
	api.HandleFunc("/actions", handlers.ListActions).Methods("GET", "OPTIONS")

	// Future modules (placeholders)
	RegisterRiskRoutes(api)
	RegisterApprovalRoutes(api)
	RegisterAuditRoutes(api)
	RegisterAdminRoutes(api)
}

func RegisterRiskRoutes(r *mux.Router)      {}
func RegisterApprovalRoutes(r *mux.Router)  {}
func RegisterAuditRoutes(r *mux.Router)     {}
func RegisterAdminRoutes(r *mux.Router)     {}