package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func SignToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})
	secretkey := os.Getenv("JWT_SECRET")

	return token.SignedString([]byte(secretkey))

}

type contextKey string

const usernamekey contextKey = "username"

func AuthenticationMIddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt")

		if err != nil {
			http.Redirect(w, r, "/signin", http.StatusTemporaryRedirect)
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
