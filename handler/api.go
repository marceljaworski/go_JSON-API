package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"
	"github.com/marceljaworski/go_JSON-API/model"
	"github.com/marceljaworski/go_JSON-API/token"
)

type APIServer struct {
	listenAddr string
	store      model.Repo
	auth       token.Auth
}

func NewAPIServer(listenAddr string, store model.Repo, auth token.Auth) *APIServer {
	return &APIServer{
		listenAddr: "localhost:" + listenAddr,
		store:      store,
		auth:       auth,
	}
}

func (s *APIServer) Run() {
	router := mux.NewRouter()

	router.HandleFunc("/signup", makeHTTPHandleFunc(s.handleSignUp)).Methods("POST")
	router.HandleFunc("/login", makeHTTPHandleFunc(s.handleLogin)).Methods("POST")
	router.HandleFunc("/account", makeHTTPHandleFunc(s.handleAccount))
	router.HandleFunc("/account/{id}", s.protectedHandler(makeHTTPHandleFunc(s.handleAccountByID)))
	router.HandleFunc("/transfer", makeHTTPHandleFunc(s.handleTransfer))

	fmt.Println("JSON API server running on port: ", s.listenAddr)

	err := http.ListenAndServe(s.listenAddr, router)
	if err != nil {
		fmt.Println("Could not start the server", err)
	}

}
func (s *APIServer) handleSignUp(w http.ResponseWriter, r *http.Request) error {

	return s.handleCreateAccount(w, r)

}
func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) error {

	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return err
	}

	account, err := s.store.GetAccountByEmail(req.Email)
	if err != nil {
		return err
	}

	err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(req.Password))
	if err != nil {
		return err
	}

	tokenString, err := s.auth.CreateToken(account.FirstName)
	if err != nil {
		return err
	}
	resp := model.LoginResponse{
		Token: tokenString,
		ID:    account.ID,
	}

	return WriteJSON(w, http.StatusOK, resp)
}
func (s *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		return s.handleGetAccount(w)
	}
	return fmt.Errorf("method not allowed %s", r.Method)
}

func (s *APIServer) handleAccountByID(w http.ResponseWriter, r *http.Request) error {

	if r.Method == "GET" {
		return s.handleGetAccountByID(w, r)
	}
	if r.Method == "DELETE" {
		return s.handleDeleteAccount(w, r)
	}
	return fmt.Errorf("method not allowed %s", r.Method)
}

func (s *APIServer) handleGetAccount(w http.ResponseWriter) error {
	accounts, err := s.store.GetAccounts()
	if err != nil {
		return err
	}
	return WriteJSON(w, http.StatusOK, accounts)
}

func (s *APIServer) handleGetAccountByID(w http.ResponseWriter, r *http.Request) error {

	idStr := mux.Vars(r)["id"]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return fmt.Errorf("invalid id given %s", idStr)
	}
	account, err := s.store.GetAccountByID(id)
	if err != nil {
		return err
	}
	return WriteJSON(w, http.StatusOK, account)
}

func (s *APIServer) handleCreateAccount(w http.ResponseWriter, r *http.Request) error {
	createAccountReq := new(model.CreateAccountRequest)

	if err := json.NewDecoder(r.Body).Decode(createAccountReq); err != nil {
		return err
	}

	account, err := model.NewAccount(createAccountReq.FirstName, createAccountReq.LastName, createAccountReq.Email, createAccountReq.Password)
	if err != nil {
		return err
	}

	if err := s.store.CreateAccount(account); err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, account)
}

func (s *APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) error {
	idStr := mux.Vars(r)["id"]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return fmt.Errorf("invalid id given %s", idStr)
	}
	if err := s.store.DeleteAccount(id); err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, map[string]int{"deleted": id})
}

func (s *APIServer) handleTransfer(w http.ResponseWriter, r *http.Request) error {
	transferReq := new(model.TransferRequest)
	if err := json.NewDecoder(r.Body).Decode(transferReq); err != nil {
		return err
	}
	defer r.Body.Close()
	return WriteJSON(w, http.StatusOK, transferReq)
}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// JWT auth middleware
func (s *APIServer) protectedHandler(handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			WriteJSON(w, http.StatusUnauthorized, ApiError{Error: "Missing authorization header"})
			return
		}
		err := s.auth.VerifyToken(tokenString)
		if err != nil {
			WriteJSON(w, http.StatusUnauthorized, ApiError{Error: "Invalid Token"})
			return
		}
		// idStr := mux.Vars(r)["id"]
		// id, err := strconv.Atoi(idStr)
		// if err != nil {
		// 	WriteJSON(w, http.StatusForbidden, ApiError{Error: "permission denied"})
		// 	return
		// }
		// account, err := s.store.GetAccountByID(id)
		// if err != nil {
		// 	WriteJSON(w, http.StatusForbidden, ApiError{Error: "permission denied"})
		// 	return
		// }
		fmt.Println("Welcome to the the protected area")
		handlerFunc(w, r)
	}
}

type apiFunc func(http.ResponseWriter, *http.Request) error

type ApiError struct {
	Error string `json:"error"`
}

func makeHTTPHandleFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			WriteJSON(w, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
	}
}
