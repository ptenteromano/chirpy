package main

import (
	"fmt"
	"net/http"
)

type apiConfig struct {
	fileServerHits int
}

// An example of middleware that updates the handler it gets passed
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

func (c *apiConfig) handlerMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`
<html>

<body>
	<h1>Welcome, Chirpy Admin</h1>
	<p>Chirpy has been visited %d times!</p>
</body>

</html>
	`, c.fileServerHits)))
}
