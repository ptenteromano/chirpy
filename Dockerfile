FROM debian:stable-slim

# Add metadata to the image
LABEL maintainer="github.com/pteneromano"
LABEL description="Chirpy - go server from boot.dev course"

# Make sure it's built for linux
# GOOS=linux GOARCH=amd64 go build -o chirpy
COPY chirpy /bin/chirpy

EXPOSE 8080

CMD ["/bin/chirpy"]
