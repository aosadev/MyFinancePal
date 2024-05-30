package main

import (
    "context"
    "crypto/rand"
    "database/sql"
    "encoding/base64"
    "encoding/json"
    "log"
    "net/http"
    "os"
    "os/signal"
    "strconv"
    "syscall"
    "time"

    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/mux"
    _ "github.com/mattn/go-sqlite3"
    "golang.org/x/crypto/bcrypt"
)

// Clave secreta para firmar los tokens JWT
var jwtKey []byte

// Estructura de los reclamos (claims) del token JWT
type Claims struct {
    Email string `json:"email"`
    jwt.StandardClaims
}

var db *sql.DB

func initDB() {
    var err error
    db, err = sql.Open("sqlite3", "myfinancepal.db")
    if err != nil {
        log.Fatal(err)
    }

    createTransactionTable := `CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT,
        amount REAL,
        timestamp DATETIME
    );`
    _, err = db.Exec(createTransactionTable)
    if err != nil {
        log.Fatal(err)
    }

    createUserTable := `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT
    );`
    _, err = db.Exec(createUserTable)
    if err != nil {
        log.Fatal(err)
    }

    createCategoryTable := `CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE
    );`
    _, err = db.Exec(createCategoryTable)
    if err != nil {
        log.Fatal(err)
    }
}

func generateKey() (string, error) {
    key := make([]byte, 32)
    if _, err := rand.Read(key); err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(key), nil
}

func main() {
    // Generar una clave JWT al iniciar la aplicación
    keyString, err := generateKey()
    if err != nil {
        log.Fatal("Error generating JWT key:", err)
    }
    jwtKey = []byte(keyString)
    log.Println("Generated JWT key:", keyString)

    initDB()

    go func() {
        sigs := make(chan os.Signal, 1)
        signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
        <-sigs
        db.Close()
        os.Exit(0)
    }()

    router := mux.NewRouter()

    router.HandleFunc("/transactions", getTransactions).Methods("GET")
    router.HandleFunc("/transaction/{id}", getTransaction).Methods("GET")
    router.HandleFunc("/transaction", createTransaction).Methods("POST")
    router.HandleFunc("/transaction/{id}", updateTransaction).Methods("PUT")
    router.HandleFunc("/transaction/{id}", deleteTransaction).Methods("DELETE")

    router.HandleFunc("/user", createUser).Methods("POST")
    router.HandleFunc("/user/{id}", deleteUser).Methods("DELETE")
    router.HandleFunc("/user/{id}", updateUser).Methods("PUT")
    router.HandleFunc("/user/{id}/password", updateUserPassword).Methods("PUT")
    router.HandleFunc("/user/checkpassword", checkPassword).Methods("POST")

    log.Fatal(http.ListenAndServe(":8080", router))
}

// Transaction define la estructura de una transacción
type Transaction struct {
    ID        int       `json:"id"`
    Type      string    `json:"type"`
    Amount    float64   `json:"amount"`
    Timestamp time.Time `json:"timestamp"`
}

// User define la estructura de un usuario
type User struct {
    ID       int    `json:"id"`
    Username string `json:"username"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

// getTransactions maneja GET para listar todas las transacciones
func getTransactions(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    rows, err := db.Query("SELECT id, type, amount, timestamp FROM transactions")
    if err != nil {
        log.Printf("Error querying transactions: %v", err)
        http.Error(w, "Error querying database", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var transactions []Transaction
    for rows.Next() {
        var t Transaction
        if err := rows.Scan(&t.ID, &t.Type, &t.Amount, &t.Timestamp); err != nil {
            log.Printf("Error scanning transaction: %v", err)
            http.Error(w, "Error reading transactions", http.StatusInternalServerError)
            return
        }
        transactions = append(transactions, t)
    }

    if err := rows.Err(); err != nil {
        log.Printf("Error with rows: %v", err)
        http.Error(w, "Error reading transactions", http.StatusInternalServerError)
        return
    }

    if len(transactions) == 0 {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("[]"))
        return
    }

    if err := json.NewEncoder(w).Encode(transactions); err != nil {
        log.Printf("Error encoding transactions: %v", err)
        http.Error(w, "Error encoding transactions", http.StatusInternalServerError)
    }
}

// getTransaction maneja GET para obtener una transacción específica por ID
func getTransaction(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id, err := strconv.Atoi(params["id"])
    if err != nil {
        http.Error(w, "Invalid transaction ID", http.StatusBadRequest)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    var t Transaction
    err = db.QueryRow("SELECT id, type, amount, timestamp FROM transactions WHERE id = ?", id).Scan(&t.ID, &t.Type, &t.Amount, &t.Timestamp)
    if err != nil {
        if err == sql.ErrNoRows {
            http.NotFound(w, r)
            return
        }
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    json.NewEncoder(w).Encode(t)
}

// createTransaction maneja POST para crear una nueva transacción
func createTransaction(w http.ResponseWriter, r *http.Request) {
    var transaction Transaction
    if err := json.NewDecoder(r.Body).Decode(&transaction); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    stmt, err := db.Prepare("INSERT INTO transactions (type, amount, timestamp) VALUES (?, ?, ?)")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer stmt.Close()

    transaction.Timestamp = time.Now()
    result, err := stmt.Exec(transaction.Type, transaction.Amount, transaction.Timestamp)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    lastInsertId, err := result.LastInsertId()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    transaction.ID = int(lastInsertId)

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(transaction)
}

// updateTransaction maneja PUT para actualizar una transacción existente
func updateTransaction(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id, err := strconv.Atoi(params["id"])
    if err != nil {
        http.Error(w, "Invalid transaction ID", http.StatusBadRequest)
        return
    }

    var transaction Transaction
    if err := json.NewDecoder(r.Body).Decode(&transaction); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    stmt, err := db.Prepare("UPDATE transactions SET type = ?, amount = ?, timestamp = ? WHERE id = ?")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer stmt.Close()

    transaction.ID = id
    transaction.Timestamp = time.Now()
    _, err = stmt.Exec(transaction.Type, transaction.Amount, transaction.Timestamp, id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(transaction)
}

// deleteTransaction maneja DELETE para eliminar una transacción
func deleteTransaction(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id, err := strconv.Atoi(params["id"])
    if err != nil {
        http.Error(w, "Invalid transaction ID", http.StatusBadRequest)
        return
    }

    stmt, err := db.Prepare("DELETE FROM transactions WHERE id = ?")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer stmt.Close()

    _, err = stmt.Exec(id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

// createUser maneja POST para crear un nuevo usuario
func createUser(w http.ResponseWriter, r *http.Request) {
    var user User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    // Validar que el nombre de usuario, el correo electrónico y la contraseña no estén vacíos
    if user.Username == "" || user.Email == "" || user.Password == "" {
        http.Error(w, "Username, email, and password are required", http.StatusBadRequest)
        return
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Error hashing password", http.StatusInternalServerError)
        return
    }

    stmt, err := db.Prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer stmt.Close()

    _, err = stmt.Exec(user.Username, user.Email, string(hashedPassword))
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    w.Write([]byte("Usuario creado"))
}

// updateUser maneja PUT para actualizar un usuario existente
func updateUser(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id := params["id"]

    var user User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    stmt, err := db.Prepare("UPDATE users SET username = ?, email = ? WHERE id = ?")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer stmt.Close()

    _, err = stmt.Exec(user.Username, user.Email, id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(user)
}

// updateUserPassword maneja PUT para actualizar la contraseña de un usuario
func updateUserPassword(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id := params["id"]

    var payload struct {
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Error hashing password", http.StatusInternalServerError)
        return
    }

    stmt, err := db.Prepare("UPDATE users SET password = ? WHERE id = ?")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer stmt.Close()

    _, err = stmt.Exec(string(hashedPassword), id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Password updated"))
}

// deleteUser maneja DELETE para eliminar un usuario
func deleteUser(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id := params["id"]

    stmt, err := db.Prepare("DELETE FROM users WHERE id = ?")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer stmt.Close()

    _, err = stmt.Exec(id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

// checkPassword maneja POST para verificar la contraseña y generar un token JWT si es correcta
func checkPassword(w http.ResponseWriter, r *http.Request) {
    var credentials struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    var hashedPassword string
    var user User
    err := db.QueryRow("SELECT id, username, email, password FROM users WHERE email = ?", credentials.Email).Scan(&user.ID, &user.Username, &user.Email, &hashedPassword)
    if err != nil {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password))
    if err != nil {
        http.Error(w, "Invalid password", http.StatusUnauthorized)
        return
    }

    expirationTime := time.Now().Add(24 * time.Hour) // Token expira en 24 horas
    claims := &Claims{
        Email: credentials.Email,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        http.Error(w, "Error generating token", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "token": tokenString,
    })
}

// Middleware para verificar el token JWT
func jwtMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tokenStr := r.Header.Get("Authorization")
        if tokenStr == "" {
            http.Error(w, "Missing token", http.StatusUnauthorized)
            return
        }

        claims := &Claims{}
        token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
            return jwtKey, nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        ctx := context.WithValue(r.Context(), "user", claims.Email)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}


