package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/websocket"
)

type Client struct {
	conn     *websocket.Conn
	username string
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (h *Handler) handleconnection(w http.ResponseWriter, r *http.Request) {

	uname, ok := r.Context().Value(usernamekey).(string)
	username := User{Username: r.URL.Query().Get("username")}

	if username.Username != uname {

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
	if ok := h.checkuser(username.Username); !ok {
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
	messages, err := h.getUndeliveredMessages(username.Username)

	if err != nil {
		println(err.Error())

	} else {
		for _, msg := range messages {

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
			err = h.markMessagesAsDelivered(username.Username)
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

		if ok := h.checkuser(message.To); !ok {
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

			err = recipient.conn.WriteMessage(websocket.TextMessage, jsonmsg)
			if err != nil {
				fmt.Println(err)
				err := h.saveMessages(message)
				if err != nil {
					println(err.Error())
				}
				break
			}

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

			err := me.conn.WriteMessage(websocket.TextMessage, jsonres)
			if err != nil {
				println(err.Error())
			}
			err = h.saveMessages(message)
			if err != nil {
				println(err.Error())
			}
		}

	}

}
