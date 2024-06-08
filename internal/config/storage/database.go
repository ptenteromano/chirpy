package storage

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

type DBStructure struct {
	Chirps        map[string]Chirp `json:"chirps"`
	Users         map[string]User  `json:"users"`
	RefreshTokens map[string]RefreshToken
}

type Chirp struct {
	Id       int    `json:"id"`
	Body     string `json:"body"`
	AuthorId int    `json:"author_id"`
}

type User struct {
	Id       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshToken struct {
	UserId    int    `json:"user_id"`
	Value     string `json:"Value"`
	ExpiresAt time.Time
	Revoked   bool `json:"Revoked"`
}

func EmptyDBStructure() DBStructure {
	return DBStructure{
		Chirps:        map[string]Chirp{},
		Users:         map[string]User{},
		RefreshTokens: map[string]RefreshToken{},
	}
}

const STORAGE_FILE = "database.json"

type DB struct {
	path string
	mux  *sync.RWMutex
}

func Connect() *DB {
	db := DB{
		path: STORAGE_FILE,
		mux:  &sync.RWMutex{},
	}

	db.ensureDB()

	return &db
}

func (db *DB) ensureDB() {
	// Attempt to open the file in read-only mode
	if _, err := os.Stat(db.path); os.IsNotExist(err) {
		// File does not exist, create it
		file, err := os.Create(db.path)
		if err != nil {
			// Handle potential errors when creating the file
			log.Fatalf("Failed to create file: %s", err)
		}
		defer file.Close()

		log.Println("Created database.json")
	} else {
		// File exists
		log.Println("database.json already exists.")
	}
}

func (db *DB) contentsToStruct() (DBStructure, error) {
	// Open the file in read-only mode
	file, err := os.Open(db.path)

	if err == io.EOF {
		return EmptyDBStructure(), nil
	}

	if err != nil {
		return EmptyDBStructure(), err
	}

	defer file.Close()

	// Decode the JSON file
	var dbStruct DBStructure
	err = json.NewDecoder(file).Decode(&dbStruct)

	if err != nil {
		return EmptyDBStructure(), err
	}

	return dbStruct, nil
}
