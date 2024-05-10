package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

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
	user := User{nextId, email, hashedPassword}

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
