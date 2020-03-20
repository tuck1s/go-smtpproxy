// Package smtpproxy is based heavily on https://github.com/emersion/go-smtp, with increased transparency of response codes and no sasl dependency.
package smtpproxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

var errTCPAndLMTP = errors.New("smtp: cannot start LMTP server listening on a TCP socket")

// Logger interface is used by Server to report unexpected internal errors.
type Logger interface {
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}

// Server is an SMTP server.
type Server struct {
	// TCP or Unix address to listen on.
	Addr string
	// The server TLS configuration.
	TLSConfig *tls.Config

	Domain string

	Debug        io.Writer
	ErrorLog     Logger
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// If set, the AUTH command will not be advertised and authentication
	// attempts will be rejected. This setting overrides AllowInsecureAuth.
	AuthDisabled bool

	// The server backend.
	Backend Backend

	listener net.Listener
	caps     []string

	//auths no longer using sasl library

	locker sync.Mutex
	conns  map[*Conn]struct{}
}

// NewServer creates a new SMTP server, with a Backend interface, supporting many connections
func NewServer(be Backend) *Server {
	return &Server{
		Backend:  be,
		ErrorLog: log.New(os.Stderr, "smtp/server ", log.LstdFlags),
		caps:     []string{"PIPELINING", "8BITMIME", "ENHANCEDSTATUSCODES"},
		conns:    make(map[*Conn]struct{}),
	}
}

// ServeTLS configures the server with TLS credentials from supplied cert/key
// and sets the EHLO server name
func (s *Server) ServeTLS(cert []byte, privkey []byte) error {
	cer, err := tls.X509KeyPair(cert, privkey)
	if err != nil {
		return err
	}
	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	s.TLSConfig = config
	leafCer, err := x509.ParseCertificate(cer.Certificate[0])
	if err != nil {
		return err
	}
	s.Domain = leafCer.Subject.CommonName
	return nil
}

// Serve accepts incoming connections on the Listener l.
func (s *Server) Serve(l net.Listener) error {
	s.listener = l
	defer s.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}

		go s.handleConn(newConn(c, s))
	}
}

// handleConn handles incoming SMTP connections
func (s *Server) handleConn(c *Conn) error {
	s.locker.Lock()
	s.conns[c] = struct{}{}
	s.locker.Unlock()

	defer func() {
		c.Close()

		s.locker.Lock()
		delete(s.conns, c)
		s.locker.Unlock()
	}()

	c.greet()

	for {
		line, err := c.ReadLine()
		if err == nil {
			cmd, arg, err := ParseCmd(line)
			if err != nil {
				c.nbrErrors++
				c.WriteResponse(501, EnhancedCode{5, 5, 2}, "Bad command")
				continue
			}

			c.handle(cmd, arg)
		} else {
			if err == io.EOF {
				return nil
			}

			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				c.WriteResponse(221, EnhancedCode{2, 4, 2}, "Idle timeout, bye bye")
				return nil
			}

			c.WriteResponse(221, EnhancedCode{2, 4, 0}, "Connection error, sorry")
			return err
		}
	}
}

// ListenAndServe listens on the network address s.Addr and then calls Serve
// to handle requests on incoming connections.
//
// If s.Addr is blank and LMTP is disabled, ":smtp" is used.
func (s *Server) ListenAndServe() error {
	network := "tcp"
	/* if s.LMTP {
		network = "unix"
	} */

	addr := s.Addr
	if addr == "" {
		addr = ":smtp"
	}

	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}

	return s.Serve(l)
}

// Close function not needed
func (s *Server) Close() {
	s.listener.Close()

	s.locker.Lock()
	defer s.locker.Unlock()

	for conn := range s.conns {
		conn.Close()
	}
}

// ForEachConn not needed
