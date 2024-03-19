# JSON API
- Signup
- Login
- JWT
- bcrypt
- Postgres
- Docker
- Docker Compose

## How to Start

- `docker run --name postgres -e POSTGRES_PASSWORD=supersecret -p 5432:5432 -d postgres`

- `go run main.go`

## How to Start with Docker Compose

- `export POSTGRES_PASSWORD=supersecret`

- `docker-compose -f compose.yaml up`

### To do

- Sign Up (x)
- Seeding database 
`seed := flag.Bool("seed", false, "seed the db")
flag.Parse()
if seed {
    seedAccounts(store)
}`
- Docker Compose (x)