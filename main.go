package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
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
	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	if *dbg {
		log.Println("Debug mode enabled")
		// Remove the database.json file
		os.Remove("database.json")
	}

	db := &DB{path: "database.json", mux: &sync.RWMutex{}}
	db.ensureDB()

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

	mux.HandleFunc("POST /api/chirps", postChirp(db))
	mux.HandleFunc("GET /api/chirps/{id}", getChirpById(db))
	mux.HandleFunc("GET /api/chirps", getChirps(db))

	mux.HandleFunc("POST /api/users", postUser(db))
	mux.HandleFunc("POST /api/login", postLogin(db))

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

func getChirpById(database *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("GET /api/chirps/{id}")

		w.Header().Set("Content-Type", "application/json")

		id := r.URL.Path[len("/api/chirps/"):]
		chirps := database.allChirps()

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

func getChirps(database *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("GET /api/chirps")

		w.Header().Set("Content-Type", "application/json")
		chirps := database.allChirps()

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

func postChirp(database *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		chirp, err := database.WriteChirp(replaceWordsWithAsterisks(params.Body))

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

type Chirp struct {
	Id   int    `json:"id"`
	Body string `json:"body"`
}

type User struct {
	Id       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type DBStructure struct {
	Chirps map[string]Chirp `json:"chirps"`
	Users  map[string]User  `json:"users"`
}

type DB struct {
	path string
	mux  *sync.RWMutex
}

func (db *DB) ensureDB() {
	// Attempt to open the file in read-only mode
	if _, err := os.Stat(db.path); os.IsNotExist(err) {
		// File does not exist, create it
		file, err := os.Create(db.path)
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

func (db *DB) WriteChirp(body string) (Chirp, error) {
	dbStruct, err := db.contentsToStruct()

	if err != nil && err != io.EOF {
		fmt.Println("here 1:", dbStruct)
		return Chirp{}, err
	}

	db.mux.Lock()
	defer db.mux.Unlock()

	// Open the file in read-write mode
	file, err := os.OpenFile(db.path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)

	if err != nil {
		fmt.Println("here 2:", err)
		return Chirp{}, err
	}

	defer file.Close()

	nextId := len(dbStruct.Chirps) + 1
	chirp := Chirp{nextId, body}

	dbStruct.Chirps[fmt.Sprintf("%d", nextId)] = chirp

	fmt.Println("Writing chirp to database:", chirp)

	// Write the updated JSON to the file
	updatedData, err := json.Marshal(dbStruct)
	if err != nil {
		fmt.Println("here 3:", err)
		return Chirp{}, err
	}

	// Write the new JSON to the file
	err = os.WriteFile(db.path, updatedData, 0666)

	if err != nil {
		fmt.Println("here 4:", err)
		return Chirp{}, err
	}

	return chirp, nil
}

func (db *DB) allChirps() []Chirp {
	dbStruct, err := db.contentsToStruct()

	if err == io.EOF {
		return []Chirp{}
	}

	if err != nil {
		log.Fatalf("Error reading database: %s", err)
	}

	var chirps []Chirp
	for _, chirp := range dbStruct.Chirps {
		chirps = append(chirps, chirp)
	}

	return chirps
}

func (db *DB) contentsToStruct() (DBStructure, error) {
	// Open the file in read-only mode
	file, err := os.Open(db.path)

	if err == io.EOF {
		return EmptyDBStructure(), nil
	}

	if err != nil {
		return EmptyDBStructure(), err
	}

	defer file.Close()

	// Decode the JSON file
	var dbStruct DBStructure
	err = json.NewDecoder(file).Decode(&dbStruct)

	if err != nil {
		return EmptyDBStructure(), err
	}

	return dbStruct, nil
}

func EmptyDBStructure() DBStructure {
	return DBStructure{
		Chirps: map[string]Chirp{},
		Users:  map[string]User{},
	}
}

func postUser(db *DB) http.HandlerFunc {
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

// password should already be hashed
func (db *DB) WriteUser(email, hashedPassword string) (User, error) {
	dbStruct, err := db.contentsToStruct()

	if err != nil && err != io.EOF {
		fmt.Println("here 1:", dbStruct)
		return User{}, err
	}

	db.mux.Lock()
	defer db.mux.Unlock()

	// Open the file in read-write mode
	file, err := os.OpenFile(db.path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)

	if err != nil {
		return User{}, err
	}

	defer file.Close()

	for _, user := range dbStruct.Users {
		if user.Email == email {
			return User{}, fmt.Errorf("User with email %s already exists", email)
		}
	}

	nextId := len(dbStruct.Users) + 1
	user := User{nextId, email, hashedPassword}

	dbStruct.Users[fmt.Sprintf("%d", nextId)] = user

	// Write the updated JSON to the file
	updatedData, err := json.Marshal(dbStruct)
	if err != nil {
		return User{}, err
	}

	// Write the new JSON to the file
	err = os.WriteFile(db.path, updatedData, 0666)

	if err != nil {
		return User{}, err
	}

	return user, nil
}

func postLogin(db *DB) http.HandlerFunc {
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

		dbStruct, err := db.contentsToStruct()

		if err != nil {
			log.Printf("Error reading database: %s", err)
			w.WriteHeader(500)
			return
		}

		var userId int
		for _, user := range dbStruct.Users {
			if user.Email == params.Email {
				userId = user.Id
				break
			}
		}

		err = bcrypt.CompareHashAndPassword([]byte(dbStruct.Users[fmt.Sprintf("%d", userId)].Password), []byte(params.Password))

		if err != nil {
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		resp := struct {
			Id    int    `json:"id"`
			Email string `json:"email"`
		}{
			Id:    userId,
			Email: params.Email,
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
