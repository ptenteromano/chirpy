package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
)

func (db *DB) AllChirps(sortPattern string) []Chirp {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.contentsToStruct()

	if err == io.EOF {
		return []Chirp{}
	}

	if err != nil {
		log.Fatalf("Error reading database: %s", err)
	}

	var chirps []Chirp
	for _, chirp := range dbStruct.Chirps {
		if chirp.Deleted {
			continue
		}

		chirps = append(chirps, chirp)
	}

	return sortChirps(chirps, sortPattern)
}

func (db *DB) WriteChirp(userId int, body string) (Chirp, error) {
	db.mux.Lock()
	defer db.mux.Unlock()
	dbStruct, err := db.contentsToStruct()

	if err != nil && err != io.EOF {
		fmt.Println("here 1:", dbStruct)
		return Chirp{}, err
	}

	// Open the file in read-write mode
	file, err := os.OpenFile(db.path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)

	if err != nil {
		fmt.Println("here 2:", err)
		return Chirp{}, err
	}

	defer file.Close()

	nextId := len(dbStruct.Chirps) + 1
	chirp := Chirp{nextId, body, userId, false}

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

func (db *DB) DeleteChirp(userId int, chirpId string) (int, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.contentsToStruct()

	if err != nil {
		log.Printf("Error reading database: %s", err)
		return 500, fmt.Errorf("error reading database: %s", err)
	}

	// Open the file in read-write mode
	file, err := os.OpenFile(db.path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)

	if err != nil {
		return 500, err
	}

	defer file.Close()

	// Check if the chirp exists
	chirp, ok := dbStruct.Chirps[chirpId]

	if !ok {
		updatedData, _ := json.Marshal(dbStruct)
		os.WriteFile(db.path, updatedData, 0666)
		return 404, fmt.Errorf("Chirp with ID %s not found", chirpId)
	}

	// Check if the user is the owner of the chirp
	if chirp.AuthorId != userId {
		updatedData, _ := json.Marshal(dbStruct)
		os.WriteFile(db.path, updatedData, 0666)
		return 403, fmt.Errorf("User %d is not the owner of chirp %s", userId, chirpId)
	}

	// Delete the chirp
	delete(dbStruct.Chirps, chirpId)

	// Write the updated JSON to the file
	updatedData, err := json.Marshal(dbStruct)

	if err != nil {
		return 500, err
	}

	// Write the new JSON to the file
	err = os.WriteFile(db.path, updatedData, 0666)

	if err != nil {
		return 500, err
	}

	return 204, nil
}

func (db *DB) AllChirpsByAuthor(authorId int, sortPattern string) []Chirp {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.contentsToStruct()

	if err == io.EOF {
		return []Chirp{}
	}

	if err != nil {
		log.Fatalf("Error reading database: %s", err)
	}

	var chirps []Chirp
	for _, chirp := range dbStruct.Chirps {
		if chirp.AuthorId == authorId {
			chirps = append(chirps, chirp)
		}
	}

	return sortChirps(chirps, sortPattern)
}

func sortChirps(chirps []Chirp, sortPattern string) []Chirp {
	if sortPattern == "asc" {
		return chirps
	}

	if sortPattern == "desc" {
		for i := 0; i < len(chirps)/2; i++ {
			j := len(chirps) - i - 1
			chirps[i], chirps[j] = chirps[j], chirps[i]
		}
	}

	return chirps
}
