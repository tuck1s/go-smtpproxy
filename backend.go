// Package smtpproxy is based heavily on https://github.com/emersion/go-smtp, with increased transparency of response codes and no sasl dependency.
package smtpproxy

import (
	"io"
)

// Backend for a SMTP server
type Backend interface {
	// Create a session
	Init() (Session, error)
}

// Session backend functions
type Session interface {
	// Greet a session. Returns capabilities of the upstream host
	Greet(ehlotype string) ([]string, error)

	// StartTLS requests the backend to upgrade its connection
	StartTLS() error

	// Discard currently processed message.
	Reset()

	// Pass Data command upstream and receive detailed response
	DataCommand() (w io.WriteCloser, code int, msg string, err error)

	// Pass Data body (dot delimited)
	Data(r io.Reader, w io.WriteCloser) (int, string, error)

	// Pass a command directly through to the backend
	Passthru(expectcode int, cmd, arg string) (int, string, error)
}
