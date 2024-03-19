# JSON API
- Signup
- Login
- JWT
- bcrypt
- Postgres
- Docker
- Docker Compose

## How to Start
- `docker network create postgres-network`

- `docker run --name json-api --network postgres-network -e POSTGRES_PASSWORD=supersecret -p 5432:5432 -d postgres`

- `go run main.go`

### To do

- Sign Up (x)
- Seeding database 
`seed := flag.Bool("seed", false, "seed the db")
flag.Parse()
if seed {
    seedAccounts(store)
}`
- Docker Compose