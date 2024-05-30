package main

import (
    "bytes"
    "database/sql"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strconv"
    "strings"
    "testing"
    "time"

    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/mux"
    _ "github.com/mattn/go-sqlite3"
    "golang.org/x/crypto/bcrypt"
)

// Helper function to initialize a new in-memory database for testing
func initTestDB() *sql.DB {
    db, err := sql.Open("sqlite3", ":memory:")
    if err != nil {
        panic(err)
    }

    createTransactionTable := `CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT,
        amount REAL,
        timestamp DATETIME
    );`
    _, err = db.Exec(createTransactionTable)
    if err != nil {
        panic(err)
    }

    createUserTable := `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT
    );`
    _, err = db.Exec(createUserTable)
    if err != nil {
        panic(err)
    }

    createCategoryTable := `CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE
    );`
    _, err = db.Exec(createCategoryTable)
    if err != nil {
        panic(err)
    }

    return db
}

// Helper function to generate a valid JWT token for testing
func generateTestJWT(email string) string {
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        Email: email,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        panic(err)
    }

    return tokenString
}

func TestCreateUser(t *testing.T) {
    db = initTestDB() // use test database
    defer db.Close()

    router := mux.NewRouter()
    router.Use(apiKeyMiddleware)
    router.Use(rateLimitMiddleware)
    router.HandleFunc("/user", createUser).Methods("POST")

    user := User{
        Username: "johndoe",
        Email:    "john@example.com",
        Password: "securepassword123",
    }
    payload, _ := json.Marshal(user)
    req, _ := http.NewRequest("POST", "/user", bytes.NewBuffer(payload))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-API-KEY", apiKey)
    req.Header.Set("X-Real-IP", "127.0.0.1")

    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)

    if status := rr.Code; status != http.StatusCreated {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
    }

    if strings.TrimSpace(rr.Body.String()) != "Usuario creado" {
        t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), "Usuario creado")
    }
}

func TestCheckPassword(t *testing.T) {
    db = initTestDB() // use test database
    defer db.Close()

    hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("securepassword123"), bcrypt.DefaultCost)
    stmt, _ := db.Prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)")
    stmt.Exec("johndoe", "john@example.com", hashedPassword)

    router := mux.NewRouter()
    router.Use(apiKeyMiddleware)
    router.Use(rateLimitMiddleware)
    router.HandleFunc("/user/checkpassword", checkPassword).Methods("POST")

    credentials := struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }{
        Email:    "john@example.com",
        Password: "securepassword123",
    }
    payload, _ := json.Marshal(credentials)
    req, _ := http.NewRequest("POST", "/user/checkpassword", bytes.NewBuffer(payload))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-API-KEY", apiKey)
    req.Header.Set("X-Real-IP", "127.0.0.1")

    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)

    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
    }

    var response map[string]string
    json.NewDecoder(rr.Body).Decode(&response)
    token, exists := response["token"]
    if !exists {
        t.Errorf("handler did not return a token")
    }
    if token == "" {
        t.Errorf("handler returned an empty token")
    }
}

func TestCreateTransaction(t *testing.T) {
    db = initTestDB() // use test database
    defer db.Close()

    token := generateTestJWT("john@example.com")

    router := mux.NewRouter()
    router.Use(jwtMiddleware)
    router.HandleFunc("/api/transaction", createTransaction).Methods("POST")

    transaction := Transaction{
        Type:   "income",
        Amount: 1000.50,
    }
    payload, _ := json.Marshal(transaction)
    req, _ := http.NewRequest("POST", "/api/transaction", bytes.NewBuffer(payload))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("X-Real-IP", "127.0.0.1")

    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)

    if status := rr.Code; status != http.StatusCreated {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
    }

    var createdTransaction Transaction
    json.NewDecoder(rr.Body).Decode(&createdTransaction)

    if createdTransaction.Type != "income" || createdTransaction.Amount != 1000.50 {
        t.Errorf("handler returned unexpected body: got %v want %v", createdTransaction, transaction)
    }
}

func TestGetTransactions(t *testing.T) {
    db = initTestDB() // use test database
    defer db.Close()

    stmt, _ := db.Prepare("INSERT INTO transactions (type, amount, timestamp) VALUES (?, ?, ?)")
    stmt.Exec("income", 1000.50, time.Now())

    token := generateTestJWT("john@example.com")

    router := mux.NewRouter()
    router.Use(jwtMiddleware)
    router.HandleFunc("/api/transactions", getTransactions).Methods("GET")

    req, _ := http.NewRequest("GET", "/api/transactions", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("X-Real-IP", "127.0.0.1")

    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)

    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
    }

    var transactions []Transaction
    json.NewDecoder(rr.Body).Decode(&transactions)

    if len(transactions) != 1 {
        t.Errorf("handler returned unexpected number of transactions: got %v want %v", len(transactions), 1)
    }
}

func TestGetTransaction(t *testing.T) {
    db = initTestDB() // use test database
    defer db.Close()

    stmt, _ := db.Prepare("INSERT INTO transactions (type, amount, timestamp) VALUES (?, ?, ?)")
    result, _ := stmt.Exec("income", 1000.50, time.Now())
    lastInsertId, _ := result.LastInsertId()

    token := generateTestJWT("john@example.com")

    router := mux.NewRouter()
    router.Use(jwtMiddleware)
    router.HandleFunc("/api/transaction/{id}", getTransaction).Methods("GET")

    req, _ := http.NewRequest("GET", "/api/transaction/"+strconv.Itoa(int(lastInsertId)), nil)
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("X-Real-IP", "127.0.0.1")

    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)

    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
    }

    var transaction Transaction
    json.NewDecoder(rr.Body).Decode(&transaction)

    if transaction.ID != int(lastInsertId) {
        t.Errorf("handler returned wrong transaction ID: got %v want %v", transaction.ID, lastInsertId)
    }
}

func TestUpdateTransaction(t *testing.T) {
    db = initTestDB() // use test database
    defer db.Close()

    stmt, _ := db.Prepare("INSERT INTO transactions (type, amount, timestamp) VALUES (?, ?, ?)")
    result, _ := stmt.Exec("income", 1000.50, time.Now())
    lastInsertId, _ := result.LastInsertId()

    token := generateTestJWT("john@example.com")

    router := mux.NewRouter()
    router.Use(jwtMiddleware)
    router.HandleFunc("/api/transaction/{id}", updateTransaction).Methods("PUT")

    updatedTransaction := Transaction{
        Type:   "expense",
        Amount: 500.25,
    }
    payload, _ := json.Marshal(updatedTransaction)
    req, _ := http.NewRequest("PUT", "/api/transaction/"+strconv.Itoa(int(lastInsertId)), bytes.NewBuffer(payload))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("X-Real-IP", "127.0.0.1")

    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)

    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
    }

    var transaction Transaction
    json.NewDecoder(rr.Body).Decode(&transaction)

    if transaction.Type != "expense" || transaction.Amount != 500.25 {
        t.Errorf("handler returned unexpected body: got %v want %v", transaction, updatedTransaction)
    }
}

func TestDeleteTransaction(t *testing.T) {
    db = initTestDB() // use test database
    defer db.Close()

    stmt, _ := db.Prepare("INSERT INTO transactions (type, amount, timestamp) VALUES (?, ?, ?)")
    result, _ := stmt.Exec("income", 1000.50, time.Now())
    lastInsertId, _ := result.LastInsertId()

    token := generateTestJWT("john@example.com")

    router := mux.NewRouter()
    router.Use(jwtMiddleware)
    router.HandleFunc("/api/transaction/{id}", deleteTransaction).Methods("DELETE")

    req, _ := http.NewRequest("DELETE", "/api/transaction/"+strconv.Itoa(int(lastInsertId)), nil)
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("X-Real-IP", "127.0.0.1")

    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)

    if status := rr.Code; status != http.StatusNoContent {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusNoContent)
    }

    var transaction Transaction
    err := db.QueryRow("SELECT id, type, amount, timestamp FROM transactions WHERE id = ?", lastInsertId).Scan(&transaction.ID, &transaction.Type, &transaction.Amount, &transaction.Timestamp)
    if err != sql.ErrNoRows {
        t.Errorf("Expected transaction to be deleted, but it still exists")
    }
}
