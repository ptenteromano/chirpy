# Chirpy

Using Go's http library to serve static files and assets

### Docker

```bash
GOOS=linux GOARCH=amd64 go build -o chirpy
docker build . -t chirpy:latest
docker run -p 8080:8080 chirpy:latest
```
