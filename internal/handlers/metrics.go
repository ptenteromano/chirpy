package handlers

import (
	"fmt"
	"net/http"
)

type ApiConfig struct {
	FileServerHits int
}

// An example of middleware that updates the handler it gets passed
func (c *ApiConfig) MiddlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.FileServerHits++

		next.ServeHTTP(w, r)
	})
}

func (c *ApiConfig) GetServerHits(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	hitsToBytes := []byte("Hits: " + fmt.Sprintf("%d", c.FileServerHits))

	w.Write(hitsToBytes)
}

func (c *ApiConfig) ResetServerHits(w http.ResponseWriter, r *http.Request) {
	c.FileServerHits = 0

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset"))
}

func (c *ApiConfig) HandlerMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`
<html>

<body>
	<h1>Welcome, Chirpy Admin</h1>
	<p>Chirpy has been visited %d times!</p>
</body>

</html>
	`, c.FileServerHits)))
}
