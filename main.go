package main

import (
	"log"

	"github.com/marceljaworski/go_JSON-API/handler"
	"github.com/marceljaworski/go_JSON-API/storage"
	"github.com/marceljaworski/go_JSON-API/token"
)

func main() {
	store, err := storage.NewPostgresStore()
	var auth token.Auth
	if err != nil {
		log.Fatal(err)
	}

	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	server := handler.NewAPIServer("3000", store, auth)
	server.Run()
}
