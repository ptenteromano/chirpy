package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/ptenteromano/chirpy/internal/storage"
)

func HandlePolka(db *storage.DB, polkaApiKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := grabApiKey(r)

		if apiKey != polkaApiKey {
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		type parameters struct {
			Event string `json:"event"`
			Data  struct {
				UserId int `json:"user_id"`
			} `json:"data"`
		}

		var params parameters
		err := json.NewDecoder(r.Body).Decode(&params)

		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}

		if params.Event != "user.upgraded" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// return 404 if user is not found
		// return 204 after upgrading IsChirpyRed field
		user, err := db.AddChirpyRed(params.Data.UserId)

		if err != nil {
			log.Printf("Error upgrading user: %s", err)
			w.WriteHeader(404)
			return
		}

		dat, err := json.Marshal(user)
		if err != nil {
			log.Printf("Error marshalling response: %s", err)
			w.WriteHeader(500)
			return
		}

		w.WriteHeader(http.StatusNoContent)
		w.Write(dat)
	}
}
