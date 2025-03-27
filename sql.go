package main

import "fmt"

func (h *Handler) checkuser(username string) bool {

	var user string
	err := h.db.QueryRow("SELECT username FROM users WHERE username = $1", username).Scan(&user)
	if err != nil {
		fmt.Println(err)
		return false
	}
	return username == user

}

func (h *Handler) saveMessages(messagedetails Message) error {
	_, err := h.db.Exec("INSERT INTO messages (sender,receiver,content) VALUES ($1,$2,$3)", messagedetails.From, messagedetails.To, messagedetails.Content)
	return err
}

func (h *Handler) getUndeliveredMessages(reciever string) ([]Message, error) {
	rows, err := h.db.Query("SELECT id,sender,content,sent_at FROM messages WHERE receiver = $1 AND delivered = false", reciever)
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

func (h *Handler) markMessagesAsDelivered(reciever string) error {
	_, err := h.db.Exec("UPDATE messages SET delivered = true WHERE receiver = $1 AND delivered = false", reciever)
	return err
}
