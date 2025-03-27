package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"sync"
	"time"

	_ "github.com/lib/pq"

	"github.com/joho/godotenv"
)

type Handler struct {
	db *sql.DB
}

var clients sync.Map

type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Age      int    `json:"age"`
	Name     string `json:"name"`
}

type Message struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	Content   string    `json:"content"`
	Id        string    `json:"id"`
	Sent_at   time.Time `json:"sent_at"`
	Delivered bool      `json:"delivered_at"`
}

type Response struct {
	Username      string `json:"username"`
	Authenticated bool   `json:"authenticated"`
}

func main() {
	var err error
	err = godotenv.Load()
	if err != nil {
		fmt.Println(err)
		return
	}

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)
	http.Handle("/index", AuthenticationMIddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/index.html")
	})))

	http.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/login.html")
	})

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/signup.html")
	})

	db, err := connectDb()

	if err != nil {
		fmt.Println(err)
		return
	}
	h := newHandler(db)
	defer h.db.Close()

	err = h.db.Ping()
	if err != nil {
		fmt.Println(err)
		return
	}

	http.HandleFunc("/login", h.HandleLogin)
	http.HandleFunc("/signup", h.HandleSignup)

	http.Handle("/ws", AuthenticationMIddleware(http.HandlerFunc(h.handleconnection)))

	fmt.Println("websocket is up and running at port 8081")
	if err := http.ListenAndServe("[::]:8081", nil); err != nil {
		fmt.Println(err)
		return
	}
}
