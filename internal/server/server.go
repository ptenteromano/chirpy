package server

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/ptenteromano/chirpy/internal/handlers"
	"github.com/ptenteromano/chirpy/internal/storage"
)

func Start() {
	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	if *dbg {
		log.Println("Debug mode enabled")
		// Remove the database.json file
		os.Remove(storage.STORAGE_FILE)
	}

	db := storage.Connect()

	mux := http.NewServeMux()
	corsMux := handlers.MiddlewareCors(mux)

	cfg := &handlers.ApiConfig{}

	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
	polkaApiKey := os.Getenv("POLKA_API_KEY")

	server := &http.Server{
		Addr:    ":8080",
		Handler: corsMux,
	}

	fileServerHandler := cfg.MiddlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("./"))))
	mux.Handle("/app/*", fileServerHandler)

	// These are matched to the root
	mux.HandleFunc("GET /api/healthz", handlers.HealthStatus)
	mux.HandleFunc("GET /api/metrics", cfg.GetServerHits)
	mux.HandleFunc("GET /admin/metrics", cfg.HandlerMetrics)
	mux.HandleFunc("/api/reset", cfg.ResetServerHits)

	// Chirps
	mux.HandleFunc("POST /api/chirps", handlers.PostChirp(db, jwtSecret))
	mux.HandleFunc("GET /api/chirps/{id}", handlers.GetChirpById(db))
	mux.HandleFunc("GET /api/chirps", handlers.GetChirps(db))
	mux.HandleFunc("DELETE /api/chirps/{chirpId}", handlers.DeleteChirp(db, jwtSecret))

	// Users
	mux.HandleFunc("POST /api/users", handlers.PostUser(db))
	mux.HandleFunc("PUT /api/users", handlers.PutUser(db, jwtSecret))

	// Sessions
	mux.HandleFunc("POST /api/login", handlers.PostLogin(db, jwtSecret))
	mux.HandleFunc("POST /api/refresh", handlers.PostRefresh(db, jwtSecret))
	mux.HandleFunc("POST /api/revoke", handlers.PostRevoke(db))

	// Webhooks
	mux.HandleFunc("POST /api/polka/webhooks", handlers.HandlePolka(db, polkaApiKey))

	fmt.Println("Server running on port 8080")
	server.ListenAndServe()
}
