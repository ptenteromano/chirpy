package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

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
