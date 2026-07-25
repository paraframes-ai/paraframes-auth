// Package email provides a small mailer abstraction with a console (dev) and
// SMTP (production) implementation for delivering verification and reset links.
package email

import (
	"context"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
)

// Message is an outbound email.
type Message struct {
	To      string
	Subject string
	Text    string
}

// Mailer delivers messages.
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

// ConsoleMailer logs messages instead of sending them. Used in development so
// verification/reset links are visible in server logs.
type ConsoleMailer struct{}

// Send logs the message.
func (ConsoleMailer) Send(_ context.Context, msg Message) error {
	slog.Info("email (console)", "to", msg.To, "subject", msg.Subject, "body", msg.Text)
	return nil
}

// SMTPMailer sends messages via an SMTP server with PLAIN auth over STARTTLS.
type SMTPMailer struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// Send delivers the message via SMTP.
func (m SMTPMailer) Send(_ context.Context, msg Message) error {
	addr := fmt.Sprintf("%s:%d", m.Host, m.Port)
	var auth smtp.Auth
	if m.Username != "" {
		auth = smtp.PlainAuth("", m.Username, m.Password, m.Host)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", m.From)
	fmt.Fprintf(&b, "To: %s\r\n", msg.To)
	fmt.Fprintf(&b, "Subject: %s\r\n", msg.Subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(msg.Text)
	return smtp.SendMail(addr, auth, m.From, []string{msg.To}, []byte(b.String()))
}
