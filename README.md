# JSON API
- JWT
- Postgres
- Docker

## How to Start
1. `docker run --name json-api -e POSTGRES_PASSWORD=supersecret -p 5432:5432 -d postgres` 
2. `go run main.go`

### To do

- Sign Up
- Seeding database 
`seed := flag.Bool("seed", false, "seed the db")
flag.Parse()
if seed {
    seedAccounts(store)
}`