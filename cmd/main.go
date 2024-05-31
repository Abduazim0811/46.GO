package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
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
var jwtKey = []byte("my_secret_key")

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/resource", basicAuth)
	http.HandleFunc("/resource/bearer", resourceBearerHandler)
	http.HandleFunc("/protected", jwtMiddleware(protectedHandler))

	log.Println("Listening on :9000")
	http.ListenAndServe(":9000", nil)
}

func basicAuth(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	fmt.Println(username, password, ok)

	if username != "admin" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Unauthorized")
		return
	}

	response := map[string]any{
		"data": "resource data",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}

	role := "user"
	if username == "admin" {
		role = "admin"
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
	})

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{Token: tokenString})
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

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	role := claims["role"].(string)

	if role != "admin" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "forbidden"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DataResponse{Data: "protected data"})
}

func jwtMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		tokenStr := splitToken[1]
		claims := &jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "unauthorized"})
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), "user", token))
		next(w, r)
	}
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
