# Chirpy

Using Go's http library to serve static files and assets

To clear the local database and run in debug mode, run the following command:

```bash
go build -o out && ./out --debug
```


## Whats included
- HTTP using the STD
- Simple storage using a `dataabse.json` file
- Users, Chirps
- `jwt` authentication


## TODO:
- Add sqlite3 database

### Docker

```bash
GOOS=linux GOARCH=amd64 go build -o chirpy
docker build . -t chirpy:latest
docker run -p 8080:8080 chirpy:latest
```
