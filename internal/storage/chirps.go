package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
)

func (db *DB) AllChirps() []Chirp {
	dbStruct, err := db.contentsToStruct()

	if err == io.EOF {
		return []Chirp{}
	}

	if err != nil {
		log.Fatalf("Error reading database: %s", err)
	}

	var chirps []Chirp
	for _, chirp := range dbStruct.Chirps {
		chirps = append(chirps, chirp)
	}

	return chirps
}

func (db *DB) WriteChirp(body string) (Chirp, error) {
	dbStruct, err := db.contentsToStruct()

	if err != nil && err != io.EOF {
		fmt.Println("here 1:", dbStruct)
		return Chirp{}, err
	}

	db.mux.Lock()
	defer db.mux.Unlock()

	// Open the file in read-write mode
	file, err := os.OpenFile(db.path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)

	if err != nil {
		fmt.Println("here 2:", err)
		return Chirp{}, err
	}

	defer file.Close()

	nextId := len(dbStruct.Chirps) + 1
	chirp := Chirp{nextId, body}

	dbStruct.Chirps[fmt.Sprintf("%d", nextId)] = chirp

	fmt.Println("Writing chirp to database:", chirp)

	// Write the updated JSON to the file
	updatedData, err := json.Marshal(dbStruct)
	if err != nil {
		fmt.Println("here 3:", err)
		return Chirp{}, err
	}

	// Write the new JSON to the file
	err = os.WriteFile(db.path, updatedData, 0666)

	if err != nil {
		fmt.Println("here 4:", err)
		return Chirp{}, err
	}

	return chirp, nil
}
