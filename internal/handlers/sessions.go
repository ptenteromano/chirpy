package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/ptenteromano/chirpy/internal/storage"
)

func PostLogin(db *storage.DB, jwtSecret string) http.HandlerFunc {
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
		user, err := db.LoginUser(params.Email, params.Password)

		if err != nil {
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		token, err := generateAccessToken(user.Id, params.ExpiresIn, jwtSecret)

		if err != nil {
			log.Printf("Error with token generation: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong with the token generation"))
			return
		}

		refreshToken, err := db.AddRefreshToken(user.Id)

		if err != nil {
			log.Printf("Error with refresh token generation: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Something went wrong with the refresh token generation"))
			return
		}

		resp := struct {
			Id           int    `json:"id"`
			Email        string `json:"email"`
			IsChirpyRed  bool   `json:"is_chirpy_red"`
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
		}{
			Id:           user.Id,
			Email:        user.Email,
			IsChirpyRed:  user.IsChirpyRed,
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

func PostRefresh(db *storage.DB, jwtSecret string) http.HandlerFunc {
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

func PostRevoke(db *storage.DB) http.HandlerFunc {
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
