package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/ptenteromano/chirpy/internal/config/storage"
	"golang.org/x/crypto/bcrypt"
)

const MAX_CHIRP_LENGTH = 140

func main() {
	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	if *dbg {
		log.Println("Debug mode enabled")
		// Remove the database.json file
		os.Remove(storage.STORAGE_FILE)
	}

	db := storage.Connect()

	mux := http.NewServeMux()
	corsMux := middlewareCors(mux)

	config := &apiConfig{}

	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")

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

	// Chirps
	mux.HandleFunc("POST /api/chirps", postChirp(db, jwtSecret))
	mux.HandleFunc("GET /api/chirps/{id}", getChirpById(db))
	mux.HandleFunc("GET /api/chirps", getChirps(db))

	// Sessions
	mux.HandleFunc("POST /api/login", postLogin(db, jwtSecret))
	mux.HandleFunc("POST /api/users", postUser(db))
	mux.HandleFunc("PUT /api/users", putUser(db, jwtSecret))

	mux.HandleFunc("POST /api/refresh", postRefresh(db, jwtSecret))
	mux.HandleFunc("POST /api/revoke", postRevoke(db))

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

func getChirpById(database *storage.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("GET /api/chirps/{id}")

		w.Header().Set("Content-Type", "application/json")

		id := r.URL.Path[len("/api/chirps/"):]
		chirps := database.AllChirps()

		for _, chirp := range chirps {
			if fmt.Sprintf("%d", chirp.Id) == id {
				dat, err := json.Marshal(chirp)
				if err != nil {
					log.Printf("Error marshalling response: %s", err)
					w.WriteHeader(500)
					return
				}

				w.WriteHeader(http.StatusOK)
				w.Write(dat)
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Chirp not found"))
	}
}

func getChirps(database *storage.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("GET /api/chirps")

		w.Header().Set("Content-Type", "application/json")
		chirps := database.AllChirps()

		dat, err := json.Marshal(chirps)
		if err != nil {
			log.Printf("Error marshalling response: %s", err)
			w.WriteHeader(500)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(dat)
	}
}

func postChirp(database *storage.DB, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userId, err, httpStatus := authUser(r, jwtSecret)

		if err != nil {
			log.Printf("Error authenticating user: %s", err)
			w.WriteHeader(httpStatus)
			w.Write([]byte("Unauthorized"))
			return
		}

		type parameters struct {
			Body string `json:"body"`
		}

		var params parameters
		err = json.NewDecoder(r.Body).Decode(&params)
		if err != nil {
			// http.Error(w, err.Error(), http.StatusBadRequest)
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if len(params.Body) > MAX_CHIRP_LENGTH {
			writeErrMessage(w, "Chirp is too long")
			return
		}

		chirp, err := database.WriteChirp(userId, replaceWordsWithAsterisks(params.Body))

		if err != nil {
			log.Printf("Error writing chirp to database: %s", err)
			w.WriteHeader(500)
			return
		}

		dat, err := json.Marshal(chirp)
		if err != nil {
			log.Printf("Error marshalling response: %s", err)
			w.WriteHeader(500)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Write(dat)
	}
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

func postUser(db *storage.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		var params parameters
		err := json.NewDecoder(r.Body).Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if len(params.Email) == 0 || len(params.Password) == 0 {
			writeErrMessage(w, "Email is required")
			return
		}

		bcryptPassword, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)

		if err != nil {
			log.Printf("Error hashing password: %s", err)
			w.WriteHeader(500)
			return
		}

		user, err := db.WriteUser(params.Email, string(bcryptPassword))

		if err != nil {
			log.Printf("Error writing user to database: %s", err)
			w.WriteHeader(500)
			return
		}

		// Don't return the password hash
		resp := struct {
			Id    int    `json:"id"`
			Email string `json:"email"`
		}{
			Id:    user.Id,
			Email: user.Email,
		}

		dat, err := json.Marshal(resp)
		if err != nil {
			log.Printf("Error marshalling response: %s", err)
			w.WriteHeader(500)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Write(dat)
	}
}

func postLogin(db *storage.DB, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Email     string `json:"email"`
			Password  string `json:"password"`
			ExpiresIn int    `json:"expires_in_seconds"`
		}

		var params parameters
		err := json.NewDecoder(r.Body).Decode(&params)

		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}

		if params.ExpiresIn <= 0 || params.ExpiresIn > 86_400 {
			params.ExpiresIn = 86_400 // 24 hours
		}

		w.Header().Set("Content-Type", "application/json")
		userId, err := db.LoginUser(params.Email, params.Password)

		if err != nil {
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		token, err := generateAccessToken(userId, params.ExpiresIn, jwtSecret)

		if err != nil {
			log.Printf("Error with token generation: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong with the token generation"))
			return
		}

		refreshToken, err := db.AddRefreshToken(userId)

		if err != nil {
			log.Printf("Error with refresh token generation: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong with the refresh token generation"))
			return
		}

		resp := struct {
			Id           int    `json:"id"`
			Email        string `json:"email"`
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
		}{
			Id:           userId,
			Email:        params.Email,
			Token:        token,
			RefreshToken: refreshToken.Value,
		}

		dat, err := json.Marshal(resp)
		if err != nil {
			log.Printf("Error marshalling response: %s", err)
			w.WriteHeader(500)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(dat)
	}
}

func putUser(db *storage.DB, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userId, err, httpStatus := authUser(r, jwtSecret)

		if err != nil {
			log.Printf("Error authenticating user: %s", err)
			w.WriteHeader(httpStatus)
			w.Write([]byte("Unauthorized"))
			return
		}

		type parameters struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		var params parameters
		err = json.NewDecoder(r.Body).Decode(&params)

		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}

		bcryptPassword, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)

		if err != nil {
			log.Printf("Error hashing password: %s", err)
			w.WriteHeader(500)
			return
		}

		user, err := db.UpdateUser(userId, params.Email, string(bcryptPassword))

		if err != nil {
			log.Printf("Error updating user: %s", err)
			w.WriteHeader(500)
			return
		}

		resp := struct {
			Id    int    `json:"id"`
			Email string `json:"email"`
		}{
			Id:    userId,
			Email: user.Email,
		}

		dat, err := json.Marshal(resp)

		if err != nil {
			log.Printf("Error marshalling response: %s", err)
			w.WriteHeader(500)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(dat)
	}
}

func postRefresh(db *storage.DB, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := grabToken(r)

		if token == "" {
			w.WriteHeader(401)
			w.Write([]byte("No token provided"))
			return
		}

		userId, err := db.ValidateRefreshToken(token)

		if err != nil {
			log.Printf("Error reading refresh token response: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Bad refresh token"))
			return
		}

		if userId == -1 {
			log.Printf("Refresh token not valid: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Bad refresh token"))
			return
		}

		token, err = generateAccessToken(userId, 3600, jwtSecret)

		if err != nil {
			log.Printf("Error with token generation: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong with the token generation"))
			return
		}

		resp := struct {
			Token string `json:"token"`
		}{
			Token: token,
		}

		dat, err := json.Marshal(resp)
		if err != nil {
			log.Printf("Error marshalling response: %s", err)
			w.WriteHeader(500)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(dat)
	}
}

func postRevoke(db *storage.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := grabToken(r)

		if token == "" {
			w.WriteHeader(401)
			w.Write([]byte("No token provided"))
			return
		}

		err := db.RevokeRefreshToken(token)

		if err != nil {
			log.Printf("Error revoking token: %s", err)
			w.WriteHeader(500)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func generateAccessToken(userId, expiryInSeconds int, jwtSecret string) (string, error) {
	issuedAt := time.Now()
	expiresAt := issuedAt.Add(time.Duration(expiryInSeconds) * time.Second)

	// Generate token
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  &jwt.NumericDate{Time: issuedAt},
		ExpiresAt: &jwt.NumericDate{Time: expiresAt},
		Subject:   fmt.Sprint(userId),
	}
	claimedToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// This signing method expects a []byte
	return claimedToken.SignedString([]byte(jwtSecret))
}

func grabToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		return ""
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ""
	}

	return strings.TrimPrefix(authHeader, "Bearer ")
}

// Only for use with access_token
// @return userId, error, httpStatus
func authUser(r *http.Request, jwtSecret string) (int, error, int) {
	token := grabToken(r)

	if token == "" {
		return -1, fmt.Errorf("invalid authorization header provided"), 401
	}

	var claims jwt.RegisteredClaims
	_, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return -1, err, 401
	}

	userId, err := strconv.Atoi(claims.Subject)

	if err != nil {
		return -1, err, 500
	}

	return userId, nil, 200
}
