package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/ptenteromano/chirpy/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

func PostUser(db *storage.DB) http.HandlerFunc {
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
			Id          int    `json:"id"`
			Email       string `json:"email"`
			IsChirpyRed bool   `json:"is_chirpy_red"`
		}{
			Id:          user.Id,
			Email:       user.Email,
			IsChirpyRed: user.IsChirpyRed,
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

func PutUser(db *storage.DB, jwtSecret string) http.HandlerFunc {
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
