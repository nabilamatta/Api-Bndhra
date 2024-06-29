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
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string `json:"username" validate:"required,min=5,max=20"`
	Password string `json:"password" validate:"required,min=8"`
}

type Iuran struct {
	Nama  string `json:"nama" validate:"required"`
	Bulan string `json:"bulan" validate:"required"`
	Date  string `json:"date" validate:"required,oneof='Minggu 1' 'Minggu 2' 'Minggu 3' 'Minggu 4'"`
	Nilai string `json:"nilai" validate:"required"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var db *sql.DB

func hashPassword(password string, cost int) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

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
	// r.HandleFunc("/dashboard", DashboardHandler).Methods("GET")
	r.HandleFunc("/iuran", IuranHandler).Methods("POST")
	r.HandleFunc("/iuran/nama/{nama}", IuranHandler).Methods("GET")
	r.HandleFunc("/iuran/bulan/{bulan}", IuranHandler).Methods("GET")
	r.HandleFunc("/iuran/date/{date}", IuranHandler).Methods("GET")
	r.HandleFunc("/iuran/{no}", IuranHandler).Methods("PUT")

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
		http.Error(w, `{"Error Message": "Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	err = validate.Struct(user)
	if err != nil {
		log.Println("Validation error:", err)
		http.Error(w, `{"Error Message": "Invalid input data"}`, http.StatusBadRequest)
		return
	}

	hashedPassword, err := hashPassword(user.Password, 14)
	if err != nil {
		log.Println("Error hashing password:", err)
		http.Error(w, `{"Error Message": "Error processing request"}`, http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO Admin (username, password) VALUES (?, ?)", user.Username, hashedPassword)
	if err != nil {
		http.Error(w, `{"Error Message": "`+err.Error()+`"}`, http.StatusInternalServerError)
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
		http.Error(w, `{"Error Message": "Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	err = validate.Struct(user)
	if err != nil {
		log.Println("Validation error:", err)
		http.Error(w, `{"Error Message": "Invalid input data"}`, http.StatusBadRequest)
		return
	}

	var storedPassword string
	err = db.QueryRow("SELECT password FROM Admin WHERE username = ?", user.Username).Scan(&storedPassword)
	if err != nil {
		log.Println("Error retrieving password from database:", err)
		http.Error(w, `{"Error Message": "Invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	if !checkPasswordHash(user.Password, storedPassword) {
		http.Error(w, `{"Error Message": "Invalid username or password"}`, http.StatusUnauthorized)
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
		log.Println("Error generating JWT key:", err)
		http.Error(w, `{"Error Message": "Error processing request"}`, http.StatusInternalServerError)
		return
	}

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.Println("Error signing JWT token:", err)
		http.Error(w, `{"Error Message": "Error processing request"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Authorization", tokenString)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"token": "` + tokenString + `", "redirect": "dashboard"}`))
}

func IuranHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		// Create new iuran
		var iuran Iuran

		err := json.NewDecoder(r.Body).Decode(&iuran)
		if err != nil {
			log.Println("Error decoding JSON:", err)
			http.Error(w, `{"Error Message": "Invalid JSON format"}`, http.StatusBadRequest)
			return
		}

		err = validate.Struct(iuran)
		if err != nil {
			log.Println("Validation error:", err)
			http.Error(w, `{"Error Message": "Invalid input data"}`, http.StatusBadRequest)
			return
		}

		_, err = db.Exec("INSERT INTO Iuran (nama, bulan, date, nilai) VALUES (?, ?, ?, ?)", iuran.Nama, iuran.Bulan, iuran.Date, iuran.Nilai)
		if err != nil {
			http.Error(w, `{"Error Message": "`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message": "Iuran added successfully"}`))

	case "GET":
		// Get iuran
		vars := mux.Vars(r)
		nama, namaExists := vars["nama"]
		bulan, bulanExists := vars["bulan"]
		date, dateExists := vars["date"]

		if namaExists {
			rows, err := db.Query("SELECT nama, bulan, date, nilai FROM Iuran WHERE nama = ?", nama)
			if err != nil {
				http.Error(w, `{"error": "Error fetching data"}`, http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			var nama []Iuran
			for rows.Next() {
				var iuran Iuran
				err := rows.Scan(&iuran.Nama, &iuran.Bulan, &iuran.Date, &iuran.Nilai)
				if err != nil {
					http.Error(w, `{"error": "Error scanning data"}`, http.StatusInternalServerError)
					return
				}
				nama = append(nama, iuran)
			}

			err = rows.Err()
			if err != nil {
				http.Error(w, `{"error": "Error with rows"}`, http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(nama)
		} else if bulanExists {
			rows, err := db.Query("select nama, bulan, date, nilai from Iuran where bulan = ?", bulan)
			if err != nil {
				http.Error(w, `{"error": "Error fetching data"}`, http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			var bulan []Iuran
			for rows.Next() {
				var iuran Iuran
				err := rows.Scan(&iuran.Nama, &iuran.Bulan, &iuran.Date, &iuran.Nilai)
				if err != nil {
					http.Error(w, `{"error": "Error scanning data"}`, http.StatusInternalServerError)
					return
				}
				bulan = append(bulan, iuran)
			}
			err = rows.Err()
			if err != nil {
				http.Error(w, `{"error": "Error with rows"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(bulan)

		} else if dateExists {
			log.Println("Fetching data for date:", date)
			rows, err := db.Query("select nama, bulan, date, nilai from Iuran where date = ?", date)
			if err != nil {
				http.Error(w, `{"Error Message": "Error Fetching data"}`, http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			var date []Iuran
			for rows.Next() {
				var iuran Iuran
				err := rows.Scan(&iuran.Nama, &iuran.Bulan, &iuran.Date, &iuran.Nilai)
				if err != nil {
					http.Error(w, `{"Error Message": "Error Fetching data"}`, http.StatusInternalServerError)
					return
				}

				date = append(date, iuran)
			}
			err = rows.Err()
			if err != nil {
				http.Error(w, `{"error": "Error with rows"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(date)
		} else {
			rows, err := db.Query("SELECT nama, bulan, date, nilai FROM Iuran")
			if err != nil {
				http.Error(w, `{"error": "Error fetching data"}`, http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			var iurans []Iuran
			for rows.Next() {
				var iuran Iuran
				err := rows.Scan(&iuran.Nama, &iuran.Bulan, &iuran.Date, &iuran.Nilai)
				if err != nil {
					http.Error(w, `{"error": "Error scanning data"}`, http.StatusInternalServerError)
					return
				}
				iurans = append(iurans, iuran)
			}

			err = rows.Err()
			if err != nil {
				http.Error(w, `{"error": "Error with rows"}`, http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(iurans)
		}
	case "PUT":
		// Update iuran
		var iuran Iuran
		params := mux.Vars(r)
		no := params["no"]

		err := json.NewDecoder(r.Body).Decode(&iuran)
		if err != nil {
			log.Println("Error decoding JSON:", err)
			http.Error(w, `{"error": "Invalid JSON format"}`, http.StatusBadRequest)
			return
		}

		err = validate.Struct(iuran)
		if err != nil {
			log.Println("Validation error:", err)
			http.Error(w, `{"error": "Invalid input data"}`, http.StatusBadRequest)
			return
		}

		_, err = db.Exec("UPDATE Iuran SET nama = ?, bulan = ?, date = ?, nilai = ? WHERE no = ?", iuran.Nama, iuran.Bulan, iuran.Date, iuran.Nilai, no)
		if err != nil {
			http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message": "Iuran updated successfully"}`))
	default:
		http.Error(w, `{"Error Message": "Kagak ada Method yg lu mau boss..!!"}`, http.StatusMethodNotAllowed)
	}
}
