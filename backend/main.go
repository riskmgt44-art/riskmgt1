package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	"riskmgt/config"
	"riskmgt/database"
	"riskmgt/handlers"
	"riskmgt/routes"
	"riskmgt/utils"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found or error loading it")
	}

	config.LoadConfig()

	// Database connection
	if err := database.Connect(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	handlers.InitCollections()

	// Router setup
	router := mux.NewRouter()

	// === IMPORTANT FIX: Register API routes FIRST ===
	// This ensures specific API endpoints (e.g., /api/organizations) are matched
	// before the catch-all static file handler.
	routes.RegisterRoutes(router)

	// === Static files LAST (catch-all for frontend) ===
	// Serves all unmatched paths from the ../frontend directory
	fs := http.FileServer(http.Dir("../frontend"))
	router.PathPrefix("/").Handler(http.StripPrefix("/", fs))

	// Global middlewares (order matters!)
	router.Use(utils.LoggingMiddleware)
	router.Use(utils.RecoveryMiddleware)
	router.Use(utils.CORSMiddleware)

	// HTTP server configuration
	srv := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("RiskMGT Backend + Frontend running on http://localhost:%s", config.Port)
		log.Printf(" → Frontend:      http://localhost:%s/", config.Port)
		log.Printf(" → Create Org:    http://localhost:%s/create-organization.html", config.Port)
		log.Printf(" → Executive Dash: http://localhost:%s/dashboards/executive/index.html", config.Port)

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced shutdown: %v", err)
	}

	database.Disconnect()
	log.Println("Server stopped gracefully ✓")
}