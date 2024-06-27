package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

type User struct {
	// Id       int    `json:"id"`
	Username string `json:"username" validate:"required,min=5,max=20"`
	Password string `json:"password" validate:"required,min=8"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var db *sql.DB

func generateRandomKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

var validate *validator.Validate

func main() {
	var err error

	validate = validator.New()

	db, err = sql.Open("mysql", "root:@tcp(localhost:3306)/Bendahara")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	r := mux.NewRouter()

	r.HandleFunc("/daftar", SignupHandler).Methods("POST")

	r.HandleFunc("/login", SigninHandler).Methods("POST")

	corsMiddleware := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
		handlers.AllowCredentials(),
	)

	fmt.Println("Server is running on port 5000")
	log.Fatal(http.ListenAndServe(":5000", corsMiddleware(r)))
}

func SignupHandler(w http.ResponseWriter, r *http.Request) {
	var user User

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		log.Println("Error decoding JSON:", err)
		http.Error(w, `{"error": "Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	err = validate.Struct(user)
	if err != nil {
		log.Println("Validation error:", err)

		if len(user.Password) < 8 {
			http.Error(w, `{"error": "Minimal password terdiri 8 digit"}`, http.StatusBadRequest)
			return
		} else {
			http.Error(w, `{"error": "Invalid input data"}`, http.StatusBadRequest)
			return
		}
	}

	fmt.Printf("User baru: %+v\n", user)

	_, err = db.Exec("INSERT INTO Admin (username, password) VALUES ( ?, ?)", user.Username, user.Password)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "User created successfully"}`))
}

func SigninHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		log.Println("Error decoding JSON:", err)
		http.Error(w, `{"error": "Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	//validasi dari isi struct
	err = validate.Struct(user)
	if err != nil {
		log.Println("Validation error:", err)
		http.Error(w, `{"error": "Invalid input data"}`, http.StatusBadRequest)
		return
	}

	var storedPassword string
	err = db.QueryRow("SELECT password FROM Admin WHERE username = ?", user.Username).Scan(&storedPassword)
	if err != nil {
		http.Error(w, `{"error": "Invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	if user.Password != storedPassword {
		http.Error(w, `{"error": "Invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtKey, err := generateRandomKey(32)
	if err != nil {
		panic(err.Error())
	}
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Authorization", tokenString)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"token": "` + tokenString + `", "redirect": "dashboard"}`))
}

func AddIuranHandler(w http.ResponseWriter, r *http.Request) {

}
func GetIuranHandler(w http.ResponseWriter, r *http.Request) {

}
