package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:8081")
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
		err := h.db.QueryRow("SELECT password FROM users WHERE username = $1", user.Username).Scan(&hashedpassword)

		if err != nil {
			http.Error(w, "your username and password is incorrect", http.StatusNotFound)
			return
		}
		ok := checkPassword(user.Password, hashedpassword)
		if !ok {
			http.Error(w, "your username and password is incorrect", http.StatusForbidden)

			json.NewEncoder(w).Encode(map[string]bool{"ok": false})
			return
		}
		token, err := SignToken(user.Username)
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

func (h *Handler) HandleSignup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:8081")
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

		hashedpass, err := hashpass([]byte(user.Password))
		if err != nil {
			fmt.Println(err)
			return
		}
		_, err = h.db.Exec("INSERT INTO users (name,username,email,password,age) VALUES($1,$2,$3,$4,$5)", user.Name, user.Username, user.Email, hashedpass, user.Age)
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
