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

// SessionFunc Session backend functions
type SessionFunc func(expectcode int, cmd, arg string) (int, string, error)

// Session backend functions
type Session interface {
	// Greet a session. Returns capabilities of the upstream host
	Greet(ehlotype string) ([]string, int, string, error)

	// StartTLS requests the backend to upgrade its connection
	StartTLS() (int, string, error)

	// These backend functions follow a regular pattern matching SessionFunc above
	Auth(expectcode int, cmd, arg string) (int, string, error)

	Mail(expectcode int, cmd, arg string) (int, string, error)

	Rcpt(expectcode int, cmd, arg string) (int, string, error)

	Reset(expectcode int, cmd, arg string) (int, string, error)

	Quit(expectcode int, cmd, arg string) (int, string, error)

	// DataCommand pass upstream, returning a place to write the data AND the usual responses
	DataCommand() (w io.WriteCloser, code int, msg string, err error)

	// Data body (dot delimited) pass upstream, returning the usual responses
	Data(r io.Reader, w io.WriteCloser) (int, string, error)

	// This is called if we see any unknown command
	Unknown(expectcode int, cmd, arg string) (int, string, error)
}
