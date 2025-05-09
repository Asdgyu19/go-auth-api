package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
)

// User represents the user model
type User struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Password  string    `json:"password,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// LoginRequest represents the login request body
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterRequest represents the register request body
type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Response represents the API response
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

var db *sql.DB

func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: .env file not found")
	}

	// Configure MySQL connection
	cfg := mysql.Config{
		User:                 os.Getenv("DB_USER"),
		Passwd:               os.Getenv("DB_PASSWORD"),
		Net:                  "tcp",
		Addr:                 os.Getenv("DB_HOST"),
		DBName:               os.Getenv("DB_NAME"),
		AllowNativePasswords: true,
		ParseTime:            true,
	}

	// Set default values if environment variables are not set
	if cfg.User == "" {
		cfg.User = "root"
	}
	if cfg.Passwd == "" {
		cfg.Passwd = ""  // Default Laragon MySQL password is empty
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:3306"
	}
	if cfg.DBName == "" {
		cfg.DBName = "auth_db"
	}

	// Connect to database
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Test database connection
	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	log.Println("Successfully connected to MySQL database")

	// Create users table if not exists
	createTable()

	// Initialize router
	r := mux.NewRouter()

	// Add a handler for the root path
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Root endpoint accessed")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":   "Welcome to Go Auth API",
			"status":    "running",
			"endpoints": "/api/register, /api/login, /api/user",
		})
	}).Methods("GET", "OPTIONS")

	// Define routes
	r.HandleFunc("/api/register", registerHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/login", loginHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/user", getUserHandler).Methods("GET", "OPTIONS")

	// Setup CORS dengan konfigurasi yang lebih permisif
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		Debug:            true, // Enable debugging for CORS
	})

	// Use CORS middleware
	handler := c.Handler(r)

	// Add logging middleware
	loggingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		handler.ServeHTTP(w, r)
	})

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	// Bind to all interfaces (0.0.0.0) instead of just localhost
	addr := fmt.Sprintf("0.0.0.0:%s", port)
	
	// Tambahkan timeout yang lebih lama untuk server
	server := &http.Server{
		Addr:         addr,
		Handler:      loggingHandler,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	
	log.Printf("Server starting on %s...", addr)
	log.Fatal(server.ListenAndServe())
}

func createTable() {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id INT AUTO_INCREMENT PRIMARY KEY,
		name VARCHAR(100) NOT NULL,
		email VARCHAR(100) UNIQUE NOT NULL,
		password VARCHAR(100) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatalf("Failed to create users table: %v", err)
	}
	log.Println("Users table created or already exists")
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Register endpoint accessed")
	
	// Handle preflight request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Invalid request: %v", err)
		sendResponse(w, false, "Invalid request", nil, http.StatusBadRequest)
		return
	}

	log.Printf("Register request: %+v", req)

	// Validate input
	if req.Name == "" || req.Email == "" || req.Password == "" {
		log.Println("Missing required fields")
		sendResponse(w, false, "Name, email, and password are required", nil, http.StatusBadRequest)
		return
	}

	// Check if email already exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", req.Email).Scan(&count)
	if err != nil {
		log.Printf("Database error: %v", err)
		sendResponse(w, false, "Internal server error", nil, http.StatusInternalServerError)
		return
	}

	if count > 0 {
		log.Printf("Email already exists: %s", req.Email)
		sendResponse(w, false, "Email already exists", nil, http.StatusConflict)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Password hashing error: %v", err)
		sendResponse(w, false, "Internal server error", nil, http.StatusInternalServerError)
		return
	}

	// Insert user into database
	result, err := db.Exec(
		"INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
		req.Name, req.Email, string(hashedPassword),
	)

	if err != nil {
		log.Printf("Database error: %v", err)
		sendResponse(w, false, "Failed to register user", nil, http.StatusInternalServerError)
		return
	}

	// Get the ID of the newly inserted user
	userID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Error getting last insert ID: %v", err)
		sendResponse(w, false, "User registered but failed to get user ID", nil, http.StatusInternalServerError)
		return
	}

	// Return success response
	user := User{
		ID:    int(userID),
		Name:  req.Name,
		Email: req.Email,
	}
	log.Printf("User registered successfully: %+v", user)
	sendResponse(w, true, "User registered successfully", user, http.StatusCreated)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Login endpoint accessed")
	
	// Handle preflight request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Invalid request: %v", err)
		sendResponse(w, false, "Invalid request", nil, http.StatusBadRequest)
		return
	}

	log.Printf("Login request: %+v", req)

	// Validate input
	if req.Email == "" || req.Password == "" {
		log.Println("Missing required fields")
		sendResponse(w, false, "Email and password are required", nil, http.StatusBadRequest)
		return
	}

	// Get user from database
	var user User
	var hashedPassword string
	err := db.QueryRow(
		"SELECT id, name, email, password, created_at FROM users WHERE email = ?",
		req.Email,
	).Scan(&user.ID, &user.Name, &user.Email, &hashedPassword, &user.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("User not found: %s", req.Email)
			sendResponse(w, false, "Invalid email or password", nil, http.StatusUnauthorized)
		} else {
			log.Printf("Database error: %v", err)
			sendResponse(w, false, "Internal server error", nil, http.StatusInternalServerError)
		}
		return
	}

	// Compare passwords
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
	if err != nil {
		log.Println("Invalid password")
		sendResponse(w, false, "Invalid email or password", nil, http.StatusUnauthorized)
		return
	}

	// Return success response
	user.Password = "" // Remove password from response
	log.Printf("User logged in successfully: %+v", user)
	sendResponse(w, true, "Login successful", user, http.StatusOK)
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Get user endpoint accessed")
	// This would typically use authentication middleware to get the current user
	// For now, we'll just return a placeholder message
	sendResponse(w, true, "Authentication required", nil, http.StatusOK)
}

func sendResponse(w http.ResponseWriter, success bool, message string, data interface{}, statusCode int) {
	response := Response{
		Success: success,
		Message: message,
		Data:    data,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}
