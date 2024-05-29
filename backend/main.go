package main

import (
    "database/sql"
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

var db *sql.DB

func initDB() {
    var err error
    db, err = sql.Open("sqlite3", "myfinancepal.db")
    if err != nil {
        log.Fatal(err)
    }

    // Crea la tabla de transacciones si no existe
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

    // Crea la tabla de usuarios si no existe
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

    // Crea la tabla de categorías si no existe
    createCategoryTable := `CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE
    );`
    _, err = db.Exec(createCategoryTable)
    if err != nil {
        log.Fatal(err)
    }
}

func main() {
    initDB()

    // Cerrar la base de datos cuando la aplicación termina
    go func() {
        sigs := make(chan os.Signal, 1)
        signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
        <-sigs
        db.Close()
        os.Exit(0)
    }()

    router := mux.NewRouter()

	// Rutas para transacciones	
    router.HandleFunc("/transactions", getTransactions).Methods("GET")
    router.HandleFunc("/transaction/{id}", getTransaction).Methods("GET")
    router.HandleFunc("/transaction", createTransaction).Methods("POST")
    router.HandleFunc("/transaction/{id}", updateTransaction).Methods("PUT")
    router.HandleFunc("/transaction/{id}", deleteTransaction).Methods("DELETE")

	// Rutas para usuarios
	router.HandleFunc("/user", createUser).Methods("POST")
	router.HandleFunc("/user/{id}", deleteUser).Methods("DELETE")
	router.HandleFunc("/user/{id}", updateUser).Methods("PUT")
	router.HandleFunc("/user/{id}/password", updateUserPassword).Methods("PUT")
	router.HandleFunc("/user/checkpassword", checkPassword).Methods("POST")

    // Iniciar el servidor
    log.Fatal(http.ListenAndServe(":8080", router))
}

// Transaction define la estructura de una transacción
type Transaction struct {
    ID        int       `json:"id"`
    Type      string    `json:"type"` // "income" para ingresos, "expense" para gastos
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

// getTransactions maneja solicitudes GET para "/transactions" endpoint.
// Esta función consulta la base de datos para recuperar todas las transacciones almacenadas y
// las devuelve en formato JSON.
//
// Parámetros:
//   - w http.ResponseWriter: Utilizado para escribir la respuesta HTTP.
//   - r *http.Request: Contiene detalles de la solicitud HTTP. No se usa directamente en esta función.
//
// Respuesta:
//   - Si hay transacciones, se devuelven como un array de objetos JSON.
//   - Si no hay transacciones, devuelve un array vacío en formato JSON.
//   - Si ocurre un error durante la consulta o la codificación de las transacciones,
//     se devuelve un error HTTP 500 (Internal Server Error).
func getTransactions(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // Realizar la consulta a la base de datos para obtener todas las transacciones
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

    // Verificar si no hay transacciones
    if len(transactions) == 0 {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("[]"))
        return
    }

    // Codificar las transacciones en JSON y enviar la respuesta
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
    // Decodificar el cuerpo de la solicitud para obtener los datos de la transacción
    if err := json.NewDecoder(r.Body).Decode(&transaction); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Preparar y ejecutar la consulta SQL para insertar la transacción
    stmt, err := db.Prepare("INSERT INTO transactions (type, amount, timestamp) VALUES (?, ?, ?)")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer stmt.Close()

    // Asegurarse de que la marca de tiempo es la actual
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

    // Establecer el tipo de contenido y devolver la transacción creada
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
    // Decodificar el cuerpo de la solicitud para obtener los nuevos datos de la transacción
    if err := json.NewDecoder(r.Body).Decode(&transaction); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Preparar y ejecutar la consulta SQL para actualizar la transacción
    stmt, err := db.Prepare("UPDATE transactions SET type = ?, amount = ?, timestamp = ? WHERE id = ?")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer stmt.Close()

    // Actualizar la marca de tiempo a la hora actual
    transaction.Timestamp = time.Now()
    _, err = stmt.Exec(transaction.Type, transaction.Amount, transaction.Timestamp, id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Establecer el ID de la transacción y devolver la transacción actualizada
    transaction.ID = id
    w.Header().Set("Content-Type", "application/json")
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

    _, err = db.Exec("DELETE FROM transactions WHERE id = ?", id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusNoContent)
}


func createUser(w http.ResponseWriter, r *http.Request) {
    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
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

func updateUser(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id := params["id"]

    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
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

func checkPassword(w http.ResponseWriter, r *http.Request) {
    var credentials struct {
        Email    string
        Password string
    }
    err := json.NewDecoder(r.Body).Decode(&credentials)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    var hashedPassword string
    err = db.QueryRow("SELECT password FROM users WHERE email = ?", credentials.Email).Scan(&hashedPassword)
    if err != nil {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password))
    if err != nil {
        http.Error(w, "Invalid password", http.StatusUnauthorized)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Login successful"))
}

// updateUserPassword maneja PUT para actualizar la contraseña de un usuario
func updateUserPassword(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id := params["id"]

    var req struct {
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
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

    _, err = stmt.Exec(hashedPassword, id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Password updated successfully"))
}
