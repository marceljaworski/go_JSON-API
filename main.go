package main

import (
	"log"

	"github.com/marceljaworski/go_JSON-API/handler"
	"github.com/marceljaworski/go_JSON-API/storage"
)

func main() {
	store, err := storage.NewPostgresStore()
	if err != nil {
		log.Fatal(err)
	}

	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	server := handler.NewAPIServer("3000", store)
	server.Run()
}
