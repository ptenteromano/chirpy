# Variables
BINARY_NAME=bin/chirpy
CMD_DIR=cmd/chirpy
DOCKER_IMAGE_NAME=chirpy
DOCKER_TAG=latest

# Default target to build the project
all: build

# Build the binary for the current OS
build:
	go build -o $(BINARY_NAME) $(CMD_DIR)/*

# Build the binary for Linux
build-linux:
	GOOS=linux GOARCH=amd64 go build -o chirpy $(CMD_DIR)/*

# Build Docker image
docker-build: build-linux
	docker build . -t $(DOCKER_IMAGE_NAME):$(DOCKER_TAG)

# Run Docker container
docker-run: docker-build
	docker run -p 8080:8080 $(DOCKER_IMAGE_NAME):$(DOCKER_TAG)

# Run the binary with the --debug flag
run: build
	./$(BINARY_NAME) --debug

# Clean the build artifacts
clean:
	rm -f $(BINARY_NAME) chirpy

# Test the project
test:
	go test ./...

# Format the code
fmt:
	go fmt ./...

# Lint the code (requires golangci-lint)
lint:
	golangci-lint run ./...

# Install dependencies
deps:
	go mod tidy

# Run the binary without rebuilding
run-no-build:
	./$(BINARY_NAME)

.PHONY: all build build-linux docker-build docker-run run clean test fmt lint deps run-no-build
