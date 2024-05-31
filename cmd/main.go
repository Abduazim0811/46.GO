package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type TokenResponse struct {
	Token string `json:"token"`
}

type DataResponse struct {
	Data string `json:"data"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

var tokens []string

func basicAuth(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	fmt.Println(username, password, ok)

	if username != "admin" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Unathorized")
		return
	}

	response := map[string]any{
		"data": "resource data",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	http.HandleFunc("GET /resource", basicAuth)
	http.HandleFunc("GET /resource/bearer", resourceBearerHandler)
	http.HandleFunc("GET /login", loginHandler)

	log.Println("Listening the :9000")
	http.ListenAndServe(":9000", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	token, err := randomHex(20)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	tokens = append(tokens, token)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{Token: token})
}

func resourceBearerHandler(w http.ResponseWriter, r *http.Request) {
	bearerToken := r.Header.Get("Authorization")
	if bearerToken == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "missing authorization header"})
		return
	}

	splitToken := strings.Split(bearerToken, " ")
	if len(splitToken) != 2 || strings.ToLower(splitToken[0]) != "bearer" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "invalid authorization header format"})
		return
	}

	reqToken := splitToken[1]
	for _, token := range tokens {
		if token == reqToken {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(DataResponse{Data: "resource data"})
			return
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "unauthorized"})
			return
		}
	}
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
