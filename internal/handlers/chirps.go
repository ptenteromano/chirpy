package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/ptenteromano/chirpy/internal/storage"
)

func PostChirp(database *storage.DB, jwtSecret string) http.HandlerFunc {
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

func GetChirpById(database *storage.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("GET /api/chirps/{id}")

		w.Header().Set("Content-Type", "application/json")

		id := r.URL.Path[len("/api/chirps/"):]
		chirps := database.AllChirps("")

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

func GetChirps(database *storage.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("GET /api/chirps")

		w.Header().Set("Content-Type", "application/json")
		sortPattern := r.URL.Query().Get("sort")

		var chirps []storage.Chirp
		if s := r.URL.Query().Get("author_id"); s != "" {
			authorId, err := strconv.Atoi(s)
			if err != nil {
				log.Printf("Error parsing author_id: %s", err)
				w.WriteHeader(400)
				return
			}

			chirps = database.AllChirpsByAuthor(authorId, sortPattern)
		} else {
			chirps = database.AllChirps(sortPattern)
		}

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

func DeleteChirp(database *storage.DB, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userId, err, httpStatus := authUser(r, jwtSecret)

		if err != nil {
			log.Printf("Error authenticating user: %s", err)
			w.WriteHeader(httpStatus)
			w.Write([]byte("Unauthorized"))
			return
		}

		chirpId := r.URL.Path[len("/api/chirps/"):]

		httpStatus, err = database.DeleteChirp(userId, chirpId)

		if err != nil {
			log.Printf("Error deleting chirp: %s", err)
			w.WriteHeader(httpStatus)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
