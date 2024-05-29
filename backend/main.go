package main

import (
    "database/sql"
    "encoding/json"
    "log"
    "net/http"
    "strconv"
    "github.com/gorilla/mux"
    _ "github.com/mattn/go-sqlite3"
    "time"
)

// Transaction define la estructura de una transacción
type Transaction struct {
    ID        int       `json:"id"`
    Type      string    `json:"type"` // "income" para ingresos, "expense" para gastos
    Amount    float64   `json:"amount"`
    Timestamp time.Time `json:"timestamp"`
}


var db *sql.DB

func initDB() {
    var err error
    db, err = sql.Open("sqlite3", "myfinancepal.db")
    if err != nil {
        log.Fatal(err)
    }

    createTableSQL := `CREATE TABLE IF NOT EXISTS transactions (
        "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        "type" TEXT,
        "amount" REAL,
        "timestamp" DATETIME
    );`
    
    _, err = db.Exec(createTableSQL)
    if err != nil {
        log.Fatal(err)
    }
}

var transactions []Transaction
var nextID int = 1

func main() {

	initDB()
    defer db.Close()

    router := mux.NewRouter()

    // Rutas
    router.HandleFunc("/transactions", getTransactions).Methods("GET")
    router.HandleFunc("/transaction/{id}", getTransaction).Methods("GET")
    router.HandleFunc("/transaction", createTransaction).Methods("POST")
    router.HandleFunc("/transaction/{id}", updateTransaction).Methods("PUT")
    router.HandleFunc("/transaction/{id}", deleteTransaction).Methods("DELETE")

    // Iniciar el servidor
    log.Fatal(http.ListenAndServe(":8080", router))
}

// getTransactions maneja GET para listar todas las transacciones
func getTransactions(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(transactions)
}

// getTransaction maneja GET para obtener una transacción específica por ID
func getTransaction(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id, _ := strconv.Atoi(params["id"])
    for _, item := range transactions {
        if item.ID == id {
            json.NewEncoder(w).Encode(item)
            return
        }
    }
    w.WriteHeader(http.StatusNotFound)
}

// createTransaction maneja POST para crear una nueva transacción
func createTransaction(w http.ResponseWriter, r *http.Request) {
    var transaction Transaction
    _ = json.NewDecoder(r.Body).Decode(&transaction)
    transaction.ID = nextID
    nextID++
    transaction.Timestamp = time.Now()
    transactions = append(transactions, transaction)
    json.NewEncoder(w).Encode(transaction)
}

// updateTransaction maneja PUT para actualizar una transacción existente
func updateTransaction(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id, _ := strconv.Atoi(params["id"])
    for index, item := range transactions {
        if item.ID == id {
            transactions = append(transactions[:index], transactions[index+1:]...)
            var transaction Transaction
            _ = json.NewDecoder(r.Body).Decode(&transaction)
            transaction.ID = id
            transaction.Timestamp = time.Now()
            transactions = append(transactions, transaction)
            json.NewEncoder(w).Encode(transaction)
            return
        }
    }
    w.WriteHeader(http.StatusNotFound)
}

// deleteTransaction maneja DELETE para eliminar una transacción
func deleteTransaction(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id, _ := strconv.Atoi(params["id"])
    for index, item := range transactions {
        if item.ID == id {
            transactions = append(transactions[:index], transactions[index+1:]...)
            break
        }
    }
    w.WriteHeader(http.StatusNoContent)
}
