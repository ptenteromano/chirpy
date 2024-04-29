package main

import (
	"fmt"
	"net/http"
)

type apiConfig struct {
	fileServerHits int
}

func (c *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.fileServerHits++

		next.ServeHTTP(w, r)
	})
}

func (c *apiConfig) getServerHits(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	hitsToBytes := []byte("Hits: " + fmt.Sprintf("%d", c.fileServerHits))

	w.Write(hitsToBytes)
}

func (c *apiConfig) resetServerHits(w http.ResponseWriter, r *http.Request) {
	c.fileServerHits = 0

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset"))
}
