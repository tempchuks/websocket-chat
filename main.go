package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}
var db *sql.DB

type Client struct {
	conn     *websocket.Conn
	username string
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

func checkuser(username string) bool {

	var user string
	err := db.QueryRow("SELECT username FROM users WHERE username = $1", username).Scan(&user)
	if err != nil {
		fmt.Println(err)
		return false
	}
	return username == user

}

func saveMessages(messagedetails Message) error {
	_, err := db.Exec("INSERT INTO messages (sender,receiver,content) VALUES ($1,$2,$3)", messagedetails.From, messagedetails.To, messagedetails.Content)
	return err
}

func getUndeliveredMessages(reciever string) ([]Message, error) {
	rows, err := db.Query("SELECT id,sender,content,sent_at FROM messages WHERE receiver = $1 AND delivered = false", reciever)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var messages []Message
	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.Id, &msg.From, &msg.Content, &msg.Sent_at); err != nil {
			fmt.Println(err)
			return nil, err
		}
		messages = append(messages, msg)
	}
	return messages, nil
}

func markMessagesAsDelivered(reciever string) error {
	_, err := db.Exec("UPDATE messages SET delivered = true WHERE receiver = $1 AND delivered = false", reciever)
	return err
}

func handleconnection(w http.ResponseWriter, r *http.Request) {

	uname, ok := r.Context().Value(usernamekey).(string)
	username := User{Username: r.URL.Query().Get("username")}
	reciever := r.URL.Query().Get("recipient")
	fmt.Println(uname, username.Username)
	if username.Username != uname {
		fmt.Println(username.Username == uname)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	if !ok {
		fmt.Println("failed to get username")
		return
	}
	if ok := checkuser(username.Username); !ok {
		fmt.Println("user doesnt exist")
		return
	}
	client := &Client{
		conn:     conn,
		username: username.Username,
	}
	clients.Store(username.Username, client)
	fmt.Println(username.Username + " has connected")
	defer clients.Delete(username.Username)
	messages, err := getUndeliveredMessages(username.Username)

	if err != nil {
		println(err.Error())

	} else {
		for _, msg := range messages {
			fmt.Println(reciever, msg.To, 1)
			jsonmsg, err := json.Marshal(msg)
			if err != nil {
				fmt.Println(err)
				break
			}
			err = conn.WriteMessage(websocket.TextMessage, jsonmsg)
			if err != nil {
				fmt.Println(err)
				break
			}
			err = markMessagesAsDelivered(username.Username)
			if err != nil {
				fmt.Println(err)
			}

		}

	}
	for {
		client, ok := clients.Load(username.Username)
		me := client.(*Client)
		if !ok {

			fmt.Println("user disconnected")
			break
		}
		var message Message
		_, msg, err := conn.ReadMessage()
		if err != nil {
			fmt.Println(err, client)
			break
		}

		err = json.Unmarshal(msg, &message)
		if err != nil {
			fmt.Println(err)
			break
		}

		if ok := checkuser(message.To); !ok {
			response := map[string]string{"content": "the user you are about to message doesnt exist"}
			jsonres, _ := json.Marshal(response)
			conn.WriteMessage(websocket.TextMessage, jsonres)
			return
		}
		if client, ok := clients.Load(message.To); ok {
			recipient := client.(*Client)

			jsonmsg, err := json.Marshal(message)
			if err != nil {
				fmt.Println(err)
				break
			}
			fmt.Println(message)
			err = recipient.conn.WriteMessage(websocket.TextMessage, jsonmsg)
			if err != nil {
				fmt.Println(err)
				err := saveMessages(message)
				if err != nil {
					println(err.Error())
				}
				break
			}

			fmt.Println(me.username == uname)
			if uname == me.username {
				err = me.conn.WriteMessage(websocket.TextMessage, jsonmsg)

				if err != nil {
					fmt.Println(err)
					break
				}
			}
		} else {
			response := map[string]string{"content": message.To + " is not connected"}
			jsonres, _ := json.Marshal(response)
			fmt.Println(jsonres)
			err := me.conn.WriteMessage(websocket.TextMessage, jsonres)
			if err != nil {
				println(err.Error())
			}
			err = saveMessages(message)
			if err != nil {
				println(err.Error())
			}
		}

	}

}

func checkPassword(password string, hashedpassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedpassword), []byte(password))
	fmt.Println(err)
	return err == nil
}

func signToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})
	secretkey := os.Getenv("JWT_SECRET")
	fmt.Println(secretkey)
	return token.SignedString([]byte(secretkey))

}

type contextKey string

const usernamekey contextKey = "username"

func authenticationMIddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt")

		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		claims := &jwt.RegisteredClaims{}
		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method : %v", token.Header["alg"])
			}
			secretkey := os.Getenv("JWT_SECRET")

			return []byte(secretkey), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
			http.Error(w, "token expired", http.StatusUnauthorized)
			return
		}

		claim, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			fmt.Println("failed to extract claims")
			return
		}

		ctx := context.WithValue(r.Context(), usernamekey, claim["username"])
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func hashpass(password []byte) (string, error) {
	fmt.Println(string(password))
	hashed, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	return string(hashed), nil
}
func handleSignup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:8080")
	w.Header().Set("Access-Control-Allow-Method", "POST,GET,OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method == "POST" {

		/* 		_ = json.NewDecoder(r.Body).Decode(&user) */
		r.ParseForm()
		age, _ := strconv.Atoi(r.FormValue("Age"))
		user := User{
			Username: r.FormValue("Username"),
			Password: r.FormValue("Password"),
			Name:     r.FormValue("Name"),
			Email:    r.FormValue("Email"),
			Age:      age,
		}
		fmt.Println(r.FormValue("Password"))
		hashedpass, err := hashpass([]byte(user.Password))
		if err != nil {
			fmt.Println(err)
			return
		}
		_, err = db.Exec("INSERT INTO users (name,username,email,password,age) VALUES($1,$2,$3,$4,$5)", user.Name, user.Username, user.Email, hashedpass, user.Age)
		if err != nil {
			http.Error(w, "failed to save user into database", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"data": "user created successfully"})
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}
func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:8080")
	w.Header().Set("Access-Control-Allow-Method", "POST,GET,OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method == "POST" {

		var user User
		_ = json.NewDecoder(r.Body).Decode(&user)
		var hashedpassword string
		err := db.QueryRow("SELECT password FROM users WHERE username = $1", user.Username).Scan(&hashedpassword)

		if err != nil {
			http.Error(w, "your username and password is incorrect", http.StatusNotFound)
			return
		}
		ok := checkPassword(user.Password, hashedpassword)
		if !ok {
			http.Error(w, "your username and password is incorrect", http.StatusForbidden)
			fmt.Println("hey")
			json.NewEncoder(w).Encode(map[string]bool{"ok": false})
			return
		}
		token, err := signToken(user.Username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "jwt",
			Value:    token,
			HttpOnly: true,

			Path:   "/",
			Secure: false,

			Expires: time.Now().Add(time.Hour * 24),
		})

		response := Response{Authenticated: true, Username: user.Username}
		w.WriteHeader(http.StatusAccepted)
		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			fmt.Println(err)
		}
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
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
	http.HandleFunc("/index", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/index.html")
	})

	http.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/login.html")
	})

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/signup.html")
	})

	db, err = connectDb()

	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		fmt.Println(err)
		return
	}

	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/signup", handleSignup)

	http.Handle("/ws", authenticationMIddleware(http.HandlerFunc(handleconnection)))

	fmt.Println("websocket is up and running at port 8080")
	if err := http.ListenAndServe("[::]:8080", nil); err != nil {
		fmt.Println(err)
		return
	}
}
