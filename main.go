package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

/**
 * Routes:
 * /app/ -> Serve the static files in the app directory
 * /api/healthz -> Return a 200 OK
 * /api/metrics -> Return the number of hits to the file server TODO: remove
 * /admin/metrics -> Return html with hits to the file server
 * /reset -> Reset the number of hits to the file server
 */

const maxChirpLength = 140

func main() {
	ensureDatabaseFileExists()

	mux := http.NewServeMux()
	corsMux := middlewareCors(mux)

	config := &apiConfig{}

	server := &http.Server{
		Addr:    ":8080",
		Handler: corsMux,
	}

	fileServerHandler := config.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("./"))))
	mux.Handle("/app/*", fileServerHandler)

	// These are matched to the root
	mux.HandleFunc("GET /api/healthz", healthStatus)
	mux.HandleFunc("GET /api/metrics", config.getServerHits)
	mux.HandleFunc("GET /admin/metrics", config.handlerMetrics)
	mux.HandleFunc("/api/reset", config.resetServerHits)
	mux.HandleFunc("POST /api/validate_chirp", handleChirp)

	fmt.Println("Server running on port 8080")
	server.ListenAndServe()
}

func middlewareCors(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Middleware CORS", r.Method, r.URL.Path)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func healthStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func handleChirp(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	var params parameters
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		// http.Error(w, err.Error(), http.StatusBadRequest)
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if len(params.Body) > maxChirpLength {
		writeErrMessage(w, "Chirp is too long")
		return
	}

	respBody := struct {
		Cleaned_body string `json:"cleaned_body"`
	}{
		Cleaned_body: replaceWordsWithAsterisks(params.Body),
	}

	dat, err := json.Marshal(respBody)
	if err != nil {
		log.Printf("Error marshalling response: %s", err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(200)
	w.Write(dat)

}

func writeErrMessage(w http.ResponseWriter, errMsg string) {
	respBody := struct {
		Error string `json:"error"`
	}{
		Error: errMsg,
	}

	dat, err := json.Marshal(respBody)

	if err != nil {
		log.Printf("Error marshalling response: %s", err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(400)
	w.Write(dat)
}

var bannedWords = []string{
	"kerfuffle",
	"sharbert",
	"fornax",
}

// case - insensitive
func replaceWordsWithAsterisks(chirp string) string {

	for _, word := range strings.Split(chirp, " ") {
		for _, bannedWord := range bannedWords {
			if strings.ToLower(word) == bannedWord {
				chirp = strings.ReplaceAll(chirp, word, "****")
			}
		}
	}
	return chirp
}

func ensureDatabaseFileExists() {
	// Define the path to the file
	filePath := "database.json"

	// Attempt to open the file in read-only mode
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// File does not exist, create it
		file, err := os.Create(filePath)
		if err != nil {
			// Handle potential errors when creating the file
			log.Fatalf("Failed to create file: %s", err)
		}
		defer file.Close()

		log.Println("Created database.json")
	} else {
		// File exists
		log.Println("database.json already exists.")
	}
}
