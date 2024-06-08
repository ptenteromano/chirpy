package storage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
)

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
	// refreshToken, err := genRefreshToken()
	// if err != nil {
	// 	return User{}, err
	// }

	user := User{
		Id:       nextId,
		Email:    email,
		Password: hashedPassword,
	}

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

func (db *DB) AuthUser(email, password string) (int, error) {
	dbStruct, err := db.contentsToStruct()

	if err != nil {
		log.Printf("Error reading database: %s", err)
		return -1, err
	}

	var userId int
	for _, user := range dbStruct.Users {
		if user.Email == email {
			userId = user.Id
			break
		}
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbStruct.Users[fmt.Sprintf("%d", userId)].Password), []byte(password))

	if err != nil {
		return -1, err
	}

	return userId, nil
}

func (db *DB) UpdateUser(userId int, email, hashedPassword string) (User, error) {
	dbStruct, err := db.contentsToStruct()

	if err != nil {
		log.Printf("Error reading database: %s", err)
		return User{}, err
	}

	db.mux.Lock()
	defer db.mux.Unlock()

	userKey := fmt.Sprintf("%d", userId)
	user, exists := dbStruct.Users[userKey]
	if !exists {
		return User{}, fmt.Errorf("User with ID %d does not exist", userId)
	}

	// Update user fields
	// TODO: validate unique email
	if email != "" {
		user.Email = email
	}

	user.Password = hashedPassword

	dbStruct.Users[userKey] = user

	updatedData, err := json.Marshal(dbStruct)
	if err != nil {
		return User{}, err
	}

	err = os.WriteFile(db.path, updatedData, 0666)
	if err != nil {
		return User{}, err
	}

	return User{
		Id:    userId,
		Email: email,
	}, nil
}

func (db *DB) AddRefreshToken(userId int) (RefreshToken, error) {
	dbStruct, err := db.contentsToStruct()

	if err != nil {
		log.Printf("Error reading database: %s", err)
		return RefreshToken{}, err
	}

	db.mux.Lock()
	defer db.mux.Unlock()

	userKey := fmt.Sprintf("%d", userId)
	_, exists := dbStruct.Users[userKey]
	if !exists {
		return RefreshToken{}, fmt.Errorf("User with ID %d does not exist", userId)
	}

	token, err := genRefreshToken()
	if err != nil {
		return RefreshToken{}, err
	}

	nextId := len(dbStruct.RefreshTokens) + 1

	refreshToken := RefreshToken{
		UserId:    userId,
		Value:     token,
		ExpiresAt: time.Now().Add(1440 * time.Hour),
	}

	dbStruct.RefreshTokens[fmt.Sprintf("%d", nextId)] = refreshToken

	updatedData, err := json.Marshal(dbStruct)
	if err != nil {
		return RefreshToken{}, err
	}

	err = os.WriteFile(db.path, updatedData, 0666)
	if err != nil {
		return RefreshToken{}, err
	}

	return refreshToken, nil
}

func (db *DB) ValidateRefreshToken(token string) (int, error) {
	dbStruct, err := db.contentsToStruct()

	if err != nil {
		log.Printf("Error reading database: %s", err)
		return -1, err
	}

	for _, rt := range dbStruct.RefreshTokens {
		if rt.Value == token {
			valid := time.Now().Before(rt.ExpiresAt) && !rt.Revoked

			if valid {
				return rt.UserId, nil
			}

			return -1, fmt.Errorf("expired refresh_token")
		}
	}

	return -1, fmt.Errorf("did not find refresh_token")
}

func (db *DB) RevokeRefreshToken(token string) error {
	dbStruct, err := db.contentsToStruct()

	if err != nil {
		log.Printf("Error reading database: %s", err)
		return err
	}

	db.mux.Lock()
	defer db.mux.Unlock()

	var rtKey string
	var refreshToken RefreshToken
	for idx, rt := range dbStruct.RefreshTokens {
		if rt.Value == token {
			rtKey = idx
			refreshToken = rt
			break
		}
	}
	refreshToken.Revoked = true
	dbStruct.RefreshTokens[rtKey] = refreshToken

	updatedData, err := json.Marshal(dbStruct)
	if err != nil {
		return err
	}

	err = os.WriteFile(db.path, updatedData, 0666)
	if err != nil {
		return err
	}

	return nil
}

func genRefreshToken() (string, error) {
	// Create refresh token
	randomBytes := make([]byte, 32) // 32 bytes = 256 bits
	_, err := rand.Read(randomBytes)

	if err != nil {
		return "", err
	}

	return hex.EncodeToString(randomBytes), nil
}
