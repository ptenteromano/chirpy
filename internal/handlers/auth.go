package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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

func grabApiKey(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		return ""
	}

	if !strings.HasPrefix(authHeader, "ApiKey ") {
		return ""
	}

	return strings.TrimPrefix(authHeader, "ApiKey ")
}
