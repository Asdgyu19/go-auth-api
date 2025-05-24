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

// ===================================
// MODELS (Struktur Data)
// ===================================

// User represents the user model for authentication
type User struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Password  string    `json:"password,omitempty"` // omitempty: sembunyikan password saat diencode ke JSON
	CreatedAt time.Time `json:"created_at"`
}

// LoginRequest represents the login request body from client
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterRequest represents the registration request body from client
type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Child represents the child's profile model
type Child struct {
	ID        int       `json:"id"`
	NIK       string    `json:"nik"`
	Name      string    `json:"name"`
	DOB       string    `json:"dob"` // Tanggal Lahir, disimpan sebagai string "DD Month YYYY" (misal: "10 September 2024")
	CreatedAt time.Time `json:"created_at"`
}

// AddChildRequest represents the request body for adding a new child
type AddChildRequest struct {
	NIK  string `json:"nik"`
	Name string `json:"name"`
	DOB  string `json:"dob"` // Format yang diharapkan dari Flutter: "DD Month YYYY"
}

// Response represents the standard API response structure
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"` // omitempty: sembunyikan Data jika nil
}

// Global variable for database connection
var db *sql.DB

// ===================================
// MAIN FUNCTION - Titik Masuk Aplikasi Go
// ===================================

func main() {
	// 1. Load Environment Variables from .env file
	// godotenv akan mencari file .env di direktori yang sama
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: .env file not found. Using default credentials or relying on system environment variables.")
	}

	// 2. Configure MySQL Connection
	cfg := mysql.Config{
		User:                 os.Getenv("DB_USER"),
		Passwd:               os.Getenv("DB_PASSWORD"),
		Net:                  "tcp",
		Addr:                 os.Getenv("DB_HOST"),
		DBName:               os.Getenv("DB_NAME"),
		AllowNativePasswords: true, // Diperlukan untuk beberapa setup MySQL, seperti XAMPP/Laragon
		ParseTime:            true, // Penting agar `time.Time` dapat di-scan dari kolom TIMESTAMP/DATETIME
	}

	// Set default values if environment variables are not set (untuk kemudahan development)
	if cfg.User == "" {
		cfg.User = "root"
	}
	if cfg.Passwd == "" {
		cfg.Passwd = "" // Umumnya password kosong untuk root di Laragon/XAMPP
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:3306" // Alamat default MySQL
	}
	if cfg.DBName == "" {
		cfg.DBName = "auth_db" // Nama database default
	}

	// 3. Establish Database Connection
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatalf("Error opening database connection: %v", err)
	}
	// Pastikan koneksi database ditutup saat fungsi main() selesai dieksekusi
	defer db.Close()

	// 4. Test Database Connection (Ping)
	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	log.Println("Successfully connected to MySQL database")

	// 5. Create Necessary Tables (if they don't exist)
	createUsersTable()    // Fungsi untuk membuat tabel `users`
	createChildrenTable() // Fungsi untuk membuat tabel `children`

	// 6. Initialize Gorilla Mux Router
	r := mux.NewRouter()

	// 7. Define API Routes
	// Route untuk root endpoint (untuk pengecekan status API)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Root endpoint accessed")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":   "Welcome to Teman Tumbuh API",
			"status":    "running",
			"endpoints": "/api/register, /api/login, /api/user, /api/children", // Informasi endpoint
		})
	}).Methods("GET", "OPTIONS")

	// Routes untuk Autentikasi Pengguna
	r.HandleFunc("/api/register", registerHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/login", loginHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/user", getUserHandler).Methods("GET", "OPTIONS") // Endpoint placeholder untuk detail user (perlu autentikasi)

	// Routes untuk Manajemen Profil Anak
	r.HandleFunc("/api/children", addChildHandler).Methods("POST", "OPTIONS")   // Untuk menambahkan data anak
	r.HandleFunc("/api/children", getChildrenHandler).Methods("GET", "OPTIONS") // Untuk mendapatkan semua data anak

	// 8. Configure and Apply CORS Middleware
	// CORS (Cross-Origin Resource Sharing) diperlukan agar aplikasi Flutter (yang berjalan di origin berbeda)
	// dapat berkomunikasi dengan API Go ini.
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},                                 // Izinkan semua origin (cocok untuk development)
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}, // Metode HTTP yang diizinkan
		AllowedHeaders:   []string{"Content-Type", "Authorization"},     // Header request yang diizinkan
		AllowCredentials: true, // Izinkan kredensial (misal: cookies, auth headers)
		Debug:            true, // Aktifkan debugging CORS untuk melihat log CORS
	})

	// Wrap router dengan CORS handler
	handler := c.Handler(r)

	// 9. Add Request Logging Middleware
	// Ini akan mencatat setiap permintaan yang masuk ke server
	loggingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		handler.ServeHTTP(w, r) // Lanjutkan ke handler selanjutnya (CORS -> Router)
	})

	// 10. Start the HTTP Server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Gunakan port 8080 jika variabel lingkungan PORT tidak diatur
	}

	// Server akan mendengarkan di semua antarmuka jaringan (0.0.0.0)
	// Ini penting agar server dapat diakses dari perangkat lain di jaringan yang sama (emulator, HP fisik)
	addr := fmt.Sprintf("0.0.0.0:%s", port)

	// Konfigurasi HTTP server dengan timeout untuk ketahanan
	server := &http.Server{
		Addr:         addr,
		Handler:      loggingHandler, // Gunakan handler logging sebagai handler utama
		ReadTimeout:  60 * time.Second, // Batas waktu untuk membaca seluruh request body
		WriteTimeout: 60 * time.Second, // Batas waktu untuk menulis seluruh respons
		IdleTimeout:  120 * time.Second, // Batas waktu untuk koneksi idle sebelum ditutup
	}

	log.Printf("Server starting on %s...", addr)
	// Mulai mendengarkan permintaan HTTP. log.Fatal akan menghentikan program jika ada error.
	log.Fatal(server.ListenAndServe())
}

// ===================================
// TABLE CREATION FUNCTIONS
// ===================================

// createUsersTable creates the 'users' table if it doesn't exist in the database.
func createUsersTable() {
	query := `
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`

	_, err := db.Exec(query) // Execute the SQL query
	if err != nil {
		log.Fatalf("Failed to create users table: %v", err)
	}
	log.Println("Users table created or already exists")
}

// createChildrenTable creates the 'children' table if it doesn't exist in the database.
func createChildrenTable() {
	query := `
    CREATE TABLE IF NOT EXISTS children (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nik VARCHAR(20) UNIQUE NOT NULL, -- NIK (Nomor Induk Kependudukan) harus unik
        name VARCHAR(100) NOT NULL,
        dob VARCHAR(50) NOT NULL, -- Tanggal lahir disimpan sebagai string
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatalf("Failed to create children table: %v", err)
	}
	log.Println("Children table created or already exists")
}

// ===================================
// HANDLER FUNCTIONS - Mengelola Permintaan HTTP
// ===================================

// registerHandler handles new user registration requests (HTTP POST).
func registerHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Register endpoint accessed")

	// Handle CORS preflight (OPTIONS) requests
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req RegisterRequest
	// Decode JSON request body into RegisterRequest struct
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Invalid request body: %v", err)
		sendResponse(w, false, "Invalid request body", nil, http.StatusBadRequest)
		return
	}

	log.Printf("Register request received: %+v", req)

	// Validate required input fields
	if req.Name == "" || req.Email == "" || req.Password == "" {
		log.Println("Missing required fields for registration")
		sendResponse(w, false, "Name, email, and password are required", nil, http.StatusBadRequest)
		return
	}

	// Check if email already exists in the database
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", req.Email).Scan(&count)
	if err != nil {
		log.Printf("Database error checking existing email: %v", err)
		sendResponse(w, false, "Internal server error", nil, http.StatusInternalServerError)
		return
	}

	if count > 0 {
		log.Printf("Email already exists: %s", req.Email)
		sendResponse(w, false, "Email already exists", nil, http.StatusConflict) // HTTP 409 Conflict
		return
	}

	// Hash the user's password using bcrypt before storing it
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		sendResponse(w, false, "Internal server error during password hashing", nil, http.StatusInternalServerError)
		return
	}

	// Insert new user data into the 'users' table
	result, err := db.Exec(
		"INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
		req.Name, req.Email, string(hashedPassword),
	)

	if err != nil {
		log.Printf("Database error inserting new user: %v", err)
		sendResponse(w, false, "Failed to register user", nil, http.StatusInternalServerError)
		return
	}

	// Get the auto-generated ID of the newly inserted user
	userID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Error getting last insert ID for user: %v", err)
		sendResponse(w, false, "User registered but failed to retrieve user ID", nil, http.StatusInternalServerError)
		return
	}

	// Return success response with selected user data (excluding password)
	user := User{
		ID:    int(userID),
		Name:  req.Name,
		Email: req.Email,
	}
	log.Printf("User registered successfully: %+v", user)
	sendResponse(w, true, "User registered successfully", user, http.StatusCreated) // HTTP 201 Created
}

// loginHandler handles user login requests (HTTP POST).
func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Login endpoint accessed")

	// Handle CORS preflight (OPTIONS) requests
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req LoginRequest
	// Decode JSON request body into LoginRequest struct
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Invalid request body: %v", err)
		sendResponse(w, false, "Invalid request body", nil, http.StatusBadRequest)
		return
	}

	log.Printf("Login request received: %+v", req)

	// Validate required input fields
	if req.Email == "" || req.Password == "" {
		log.Println("Missing required fields for login")
		sendResponse(w, false, "Email and password are required", nil, http.StatusBadRequest)
		return
	}

	// Retrieve user from database based on email
	var user User
	var hashedPassword string
	err := db.QueryRow(
		"SELECT id, name, email, password, created_at FROM users WHERE email = ?",
		req.Email,
	).Scan(&user.ID, &user.Name, &user.Email, &hashedPassword, &user.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			// User not found for the given email
			log.Printf("User not found for email: %s", req.Email)
			sendResponse(w, false, "Invalid email or password", nil, http.StatusUnauthorized) // HTTP 401 Unauthorized
		} else {
			// Other database error
			log.Printf("Database error retrieving user: %v", err)
			sendResponse(w, false, "Internal server error", nil, http.StatusInternalServerError)
		}
		return
	}

	// Compare the provided plain password with the hashed password from the database
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
	if err != nil {
		log.Println("Invalid password provided for email:", req.Email)
		sendResponse(w, false, "Invalid email or password", nil, http.StatusUnauthorized) // HTTP 401 Unauthorized
		return
	}

	// On successful login, remove password from the response object for security
	user.Password = ""
	log.Printf("User logged in successfully: %+v", user)
	sendResponse(w, true, "Login successful", user, http.StatusOK) // HTTP 200 OK
}

// getUserHandler is a placeholder. In a real application, this would typically
// return the details of the currently authenticated user based on a token/session.
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Get user endpoint accessed (placeholder)")
	// TODO: Implement actual authentication middleware to retrieve the current user's data
	sendResponse(w, true, "Authentication required to get specific user data (this is a placeholder)", nil, http.StatusOK)
}

// addChildHandler handles adding a new child's profile (HTTP POST).
func addChildHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Add Child endpoint accessed")

	// Handle CORS preflight (OPTIONS) requests
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req AddChildRequest
	// Decode JSON request body into AddChildRequest struct
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Invalid request body for adding child: %v", err)
		sendResponse(w, false, "Invalid request body", nil, http.StatusBadRequest)
		return
	}

	log.Printf("Add Child request received: %+v", req)

	// Validate required input fields for child data
	if req.NIK == "" || req.Name == "" || req.DOB == "" {
		log.Println("Missing required fields for adding child")
		sendResponse(w, false, "NIK, Name, and Date of Birth are required", nil, http.StatusBadRequest)
		return
	}

	// Optional: Check if NIK already exists to prevent duplicate entries
	var nikCount int
	err := db.QueryRow("SELECT COUNT(*) FROM children WHERE nik = ?", req.NIK).Scan(&nikCount)
	if err != nil {
		log.Printf("Database error checking existing NIK: %v", err)
		sendResponse(w, false, "Internal server error", nil, http.StatusInternalServerError)
		return
	}
	if nikCount > 0 {
		log.Printf("NIK already exists: %s", req.NIK)
		sendResponse(w, false, "NIK already exists. Please use a unique NIK.", nil, http.StatusConflict) // HTTP 409 Conflict
		return
	}

	// Insert new child data into the 'children' table
	result, err := db.Exec(
		"INSERT INTO children (nik, name, dob) VALUES (?, ?, ?)",
		req.NIK, req.Name, req.DOB,
	)

	if err != nil {
		log.Printf("Database error inserting new child: %v", err)
		sendResponse(w, false, "Failed to add child data", nil, http.StatusInternalServerError)
		return
	}

	// Get the auto-generated ID of the newly inserted child
	childID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Error getting last insert ID for child: %v", err)
		sendResponse(w, false, "Child added but failed to retrieve generated ID", nil, http.StatusInternalServerError)
		return
	}

	// Return success response with the newly created child's data
	// The CreatedAt field is omitted as it's set by the database and not part of the request
	child := Child{
		ID:   int(childID),
		NIK:  req.NIK,
		Name: req.Name,
		DOB:  req.DOB,
	}
	log.Printf("Child added successfully: %+v", child)
	sendResponse(w, true, "Child added successfully", child, http.StatusCreated) // HTTP 201 Created
}

// getChildrenHandler retrieves all child profiles (HTTP GET).
// This can be used for administrative purposes or to populate a list in the app.
func getChildrenHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Get Children endpoint accessed")

	// Query all children from the 'children' table, ordered by creation time
	rows, err := db.Query("SELECT id, nik, name, dob, created_at FROM children ORDER BY created_at DESC")
	if err != nil {
		log.Printf("Database error getting children: %v", err)
		sendResponse(w, false, "Failed to fetch children data", nil, http.StatusInternalServerError)
		return
	}
	defer rows.Close() // Ensure the rows are closed after processing

	var children []Child // Slice to hold multiple Child objects
	for rows.Next() {
		var child Child
		// Scan row data into the Child struct fields
		if err := rows.Scan(&child.ID, &child.NIK, &child.Name, &child.DOB, &child.CreatedAt); err != nil {
			log.Printf("Error scanning child row: %v", err)
			sendResponse(w, false, "Internal server error processing children data", nil, http.StatusInternalServerError)
			return
		}
		children = append(children, child) // Add the scanned child to the slice
	}

	// Check for any errors encountered during row iteration
	if err = rows.Err(); err != nil {
		log.Printf("Error during rows iteration: %v", err)
		sendResponse(w, false, "Internal server error fetching children", nil, http.StatusInternalServerError)
		return
	}

	// Return success response with the list of children
	sendResponse(w, true, "Children data fetched successfully", children, http.StatusOK) // HTTP 200 OK
}

// ===================================
// UTILITY FUNCTIONS - Fungsi Pembantu
// ===================================

// sendResponse is a generic helper function to send structured JSON responses.
func sendResponse(w http.ResponseWriter, success bool, message string, data interface{}, statusCode int) {
	response := Response{
		Success: success,
		Message: message,
		Data:    data,
	}

	// Set the HTTP Content-Type header to application/json
	w.Header().Set("Content-Type", "application/json")
	// Set the HTTP status code for the response
	w.WriteHeader(statusCode)
	// Encode the Response struct into JSON and write it to the HTTP response writer
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response JSON: %v", err)
		// Optionally, send a fallback error response if JSON encoding fails
		http.Error(w, `{"success": false, "message": "Failed to encode response"}`, http.StatusInternalServerError)
	}
}