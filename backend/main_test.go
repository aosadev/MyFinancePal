package main

import (
    "bytes"       // Paquete para manipulación de buffers
    "database/sql" // Paquete para trabajar con bases de datos SQL
    "encoding/json" // Paquete para trabajar con JSON
    "net/http"      // Paquete para trabajar con HTTP
    "net/http/httptest" // Paquete para pruebas de servidores HTTP
    "strconv"       // Paquete para conversiones de tipos
    "strings"       // Paquete para manipulación de strings
    "testing"       // Paquete para escribir tests
    "time"          // Paquete para trabajar con tiempo y fechas

    "github.com/gorilla/mux" // Paquete para enrutamiento de HTTP
    _ "github.com/mattn/go-sqlite3" // Driver para SQLite3
    "golang.org/x/crypto/bcrypt" // Paquete para encriptar contraseñas
)

// Función auxiliar para inicializar una nueva base de datos en memoria para pruebas
func initTestDB() *sql.DB {
    db, err := sql.Open("sqlite3", ":memory:") // Abre una base de datos SQLite en memoria
    if err != nil {
        panic(err) // Si hay un error al abrir la base de datos, se detiene la ejecución
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
        panic(err) // Si hay un error al crear la tabla, se detiene la ejecución
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
        panic(err) // Si hay un error al crear la tabla, se detiene la ejecución
    }

    // Crea la tabla de categorías si no existe
    createCategoryTable := `CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE
    );`
    _, err = db.Exec(createCategoryTable)
    if err != nil {
        panic(err) // Si hay un error al crear la tabla, se detiene la ejecución
    }

    return db // Devuelve la base de datos inicializada
}

// Test para la función createUser
func TestCreateUser(t *testing.T) {
    db = initTestDB() // Utiliza la base de datos de prueba
    defer db.Close() // Cierra la base de datos al finalizar el test

    router := mux.NewRouter() // Crea un nuevo enrutador
    router.HandleFunc("/user", createUser).Methods("POST") // Define la ruta para crear usuario

    // Datos de prueba para crear un usuario
    user := User{
        Username: "johndoe",
        Email:    "john@example.com",
        Password: "securepassword123",
    }
    payload, _ := json.Marshal(user) // Codifica los datos del usuario a JSON
    req, _ := http.NewRequest("POST", "/user", bytes.NewBuffer(payload)) // Crea una nueva solicitud POST
    req.Header.Set("Content-Type", "application/json") // Establece el encabezado Content-Type

    rr := httptest.NewRecorder() // Crea un recorder para capturar la respuesta
    router.ServeHTTP(rr, req) // Envía la solicitud al enrutador

    // Verifica el código de estado de la respuesta
    if status := rr.Code; status != http.StatusCreated {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
    }

    // Verifica el cuerpo de la respuesta
    if strings.TrimSpace(rr.Body.String()) != "Usuario creado" {
        t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), "Usuario creado")
    }
}

// Test para la función getTransactions
func TestGetTransactions(t *testing.T) {
    db = initTestDB() // Utiliza la base de datos de prueba
    defer db.Close() // Cierra la base de datos al finalizar el test

    // Inserta una transacción de prueba
    stmt, _ := db.Prepare("INSERT INTO transactions (type, amount, timestamp) VALUES (?, ?, ?)")
    stmt.Exec("income", 1000.50, time.Now())

    router := mux.NewRouter() // Crea un nuevo enrutador
    router.HandleFunc("/transactions", getTransactions).Methods("GET") // Define la ruta para obtener transacciones

    req, _ := http.NewRequest("GET", "/transactions", nil) // Crea una nueva solicitud GET
    rr := httptest.NewRecorder() // Crea un recorder para capturar la respuesta
    router.ServeHTTP(rr, req) // Envía la solicitud al enrutador

    // Verifica el código de estado de la respuesta
    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
    }

    var transactions []Transaction // Define una variable para almacenar las transacciones
    json.NewDecoder(rr.Body).Decode(&transactions) // Decodifica el cuerpo de la respuesta a JSON

    // Verifica el número de transacciones devueltas
    if len(transactions) != 1 {
        t.Errorf("handler returned unexpected number of transactions: got %v want %v", len(transactions), 1)
    }
}

// Test para la función getTransaction
func TestGetTransaction(t *testing.T) {
    db = initTestDB() // Utiliza la base de datos de prueba
    defer db.Close() // Cierra la base de datos al finalizar el test

    // Inserta una transacción de prueba
    stmt, _ := db.Prepare("INSERT INTO transactions (type, amount, timestamp) VALUES (?, ?, ?)")
    result, _ := stmt.Exec("income", 1000.50, time.Now())
    lastInsertId, _ := result.LastInsertId() // Obtiene el ID de la última transacción insertada

    router := mux.NewRouter() // Crea un nuevo enrutador
    router.HandleFunc("/transaction/{id}", getTransaction).Methods("GET") // Define la ruta para obtener una transacción por ID

    req, _ := http.NewRequest("GET", "/transaction/"+strconv.Itoa(int(lastInsertId)), nil) // Crea una nueva solicitud GET
    rr := httptest.NewRecorder() // Crea un recorder para capturar la respuesta
    router.ServeHTTP(rr, req) // Envía la solicitud al enrutador

    // Verifica el código de estado de la respuesta
    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
    }

    var transaction Transaction // Define una variable para almacenar la transacción
    json.NewDecoder(rr.Body).Decode(&transaction) // Decodifica el cuerpo de la respuesta a JSON

    // Verifica el ID de la transacción devuelta
    if transaction.ID != int(lastInsertId) {
        t.Errorf("handler returned wrong transaction ID: got %v want %v", transaction.ID, lastInsertId)
    }
}

// Test para la función createTransaction
func TestCreateTransaction(t *testing.T) {
    db = initTestDB() // Utiliza la base de datos de prueba
    defer db.Close() // Cierra la base de datos al finalizar el test

    router := mux.NewRouter() // Crea un nuevo enrutador
    router.HandleFunc("/transaction", createTransaction).Methods("POST") // Define la ruta para crear una transacción

    // Datos de prueba para crear una transacción
    transaction := Transaction{
        Type:   "income",
        Amount: 1000.50,
    }
    payload, _ := json.Marshal(transaction) // Codifica los datos de la transacción a JSON
    req, _ := http.NewRequest("POST", "/transaction", bytes.NewBuffer(payload)) // Crea una nueva solicitud POST
    req.Header.Set("Content-Type", "application/json") // Establece el encabezado Content-Type

    rr := httptest.NewRecorder() // Crea un recorder para capturar la respuesta
    router.ServeHTTP(rr, req) // Envía la solicitud al enrutador

    // Verifica el código de estado de la respuesta
    if status := rr.Code; status != http.StatusCreated {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
    }

    var createdTransaction Transaction // Define una variable para almacenar la transacción creada
    json.NewDecoder(rr.Body).Decode(&createdTransaction) // Decodifica el cuerpo de la respuesta a JSON

    // Verifica los datos de la transacción creada
    if createdTransaction.Type != "income" || createdTransaction.Amount != 1000.50 {
        t.Errorf("handler returned unexpected body: got %v want %v", createdTransaction, transaction)
    }
}

// Test para la función updateTransaction
func TestUpdateTransaction(t *testing.T) {
    db = initTestDB() // Utiliza la base de datos de prueba
    defer db.Close() // Cierra la base de datos al finalizar el test

    // Inserta una transacción de prueba
    stmt, _ := db.Prepare("INSERT INTO transactions (type, amount, timestamp) VALUES (?, ?, ?)")
    result, _ := stmt.Exec("income", 1000.50, time.Now())
    lastInsertId, _ := result.LastInsertId() // Obtiene el ID de la última transacción insertada

    router := mux.NewRouter() // Crea un nuevo enrutador
    router.HandleFunc("/transaction/{id}", updateTransaction).Methods("PUT") // Define la ruta para actualizar una transacción

    // Datos de prueba para actualizar una transacción
    updatedTransaction := Transaction{
        Type:   "expense",
        Amount: 500.25,
    }
    payload, _ := json.Marshal(updatedTransaction) // Codifica los datos de la transacción a JSON
    req, _ := http.NewRequest("PUT", "/transaction/"+strconv.Itoa(int(lastInsertId)), bytes.NewBuffer(payload)) // Crea una nueva solicitud PUT
    req.Header.Set("Content-Type", "application/json") // Establece el encabezado Content-Type

    rr := httptest.NewRecorder() // Crea un recorder para capturar la respuesta
    router.ServeHTTP(rr, req) // Envía la solicitud al enrutador

    // Verifica el código de estado de la respuesta
    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
    }

    var transaction Transaction // Define una variable para almacenar la transacción actualizada
    json.NewDecoder(rr.Body).Decode(&transaction) // Decodifica el cuerpo de la respuesta a JSON

    // Verifica los datos de la transacción actualizada
    if transaction.Type != "expense" || transaction.Amount != 500.25 {
        t.Errorf("handler returned unexpected body: got %v want %v", transaction, updatedTransaction)
    }
}

// Test para la función deleteTransaction
func TestDeleteTransaction(t *testing.T) {
    db = initTestDB() // Utiliza la base de datos de prueba
    defer db.Close() // Cierra la base de datos al finalizar el test

    // Inserta una transacción de prueba
    stmt, _ := db.Prepare("INSERT INTO transactions (type, amount, timestamp) VALUES (?, ?, ?)")
    result, _ := stmt.Exec("income", 1000.50, time.Now())
    lastInsertId, _ := result.LastInsertId() // Obtiene el ID de la última transacción insertada

    router := mux.NewRouter() // Crea un nuevo enrutador
    router.HandleFunc("/transaction/{id}", deleteTransaction).Methods("DELETE") // Define la ruta para eliminar una transacción

    req, _ := http.NewRequest("DELETE", "/transaction/"+strconv.Itoa(int(lastInsertId)), nil) // Crea una nueva solicitud DELETE
    rr := httptest.NewRecorder() // Crea un recorder para capturar la respuesta
    router.ServeHTTP(rr, req) // Envía la solicitud al enrutador

    // Verifica el código de estado de la respuesta
    if status := rr.Code; status != http.StatusNoContent {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusNoContent)
    }

    var transaction Transaction // Define una variable para verificar si la transacción aún existe
    err := db.QueryRow("SELECT id, type, amount, timestamp FROM transactions WHERE id = ?", lastInsertId).Scan(&transaction.ID, &transaction.Type, &transaction.Amount, &transaction.Timestamp)
    if err != sql.ErrNoRows {
        t.Errorf("Expected transaction to be deleted, but it still exists")
    }
}

// Test para la función checkPassword
func TestCheckPassword(t *testing.T) {
    db = initTestDB() // Utiliza la base de datos de prueba
    defer db.Close() // Cierra la base de datos al finalizar el test

    // Inserta un usuario de prueba
    hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("securepassword123"), bcrypt.DefaultCost)
    stmt, _ := db.Prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)")
    stmt.Exec("johndoe", "john@example.com", hashedPassword)

    router := mux.NewRouter() // Crea un nuevo enrutador
    router.HandleFunc("/user/checkpassword", checkPassword).Methods("POST") // Define la ruta para verificar la contraseña

    // Datos de prueba para verificar la contraseña
    credentials := struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }{
        Email:    "john@example.com",
        Password: "securepassword123",
    }
    payload, _ := json.Marshal(credentials) // Codifica los datos de las credenciales a JSON
    req, _ := http.NewRequest("POST", "/user/checkpassword", bytes.NewBuffer(payload)) // Crea una nueva solicitud POST
    req.Header.Set("Content-Type", "application/json") // Establece el encabezado Content-Type

    rr := httptest.NewRecorder() // Crea un recorder para capturar la respuesta
    router.ServeHTTP(rr, req) // Envía la solicitud al enrutador

    // Verifica el código de estado de la respuesta
    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
    }

    // Verifica el cuerpo de la respuesta
    if strings.TrimSpace(rr.Body.String()) != "Login successful" {
        t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), "Login successful")
    }
}
