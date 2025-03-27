package main

import (
	"database/sql"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func hashpass(password []byte) (string, error) {

	hashed, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	return string(hashed), nil
}
func checkPassword(password string, hashedpassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedpassword), []byte(password))
	fmt.Println(err)
	return err == nil
}
func connectDb() (*sql.DB, error) {

	connStr := os.Getenv("DB_CONN_STRING")
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Println("failed to connect to database:", err)
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		fmt.Println("failed to connect to database:", err)
		return nil, err
	}
	fmt.Println("database connected successfully")
	return db, nil

}

func newHandler(db *sql.DB) *Handler {
	return &Handler{db: db}
}
