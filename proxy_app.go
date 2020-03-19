// Package smtpproxy is based heavily on https://github.com/emersion/go-smtp, with increased transparency of response codes and no sasl dependency.
package smtpproxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
)

// This file contains functions for an example Proxy app, including
//  TLS negotiation, command pass-through, AUTH pass-through.

//-----------------------------------------------------------------------------
// Backend handlers

// The ProxyBackend implements SMTP server methods.
type ProxyBackend struct {
	outHostPort        string
	verbose            bool
	insecureSkipVerify bool
}

// NewBackend creates a proxy backend with specified params
func NewBackend(outHostPort string, verbose bool, insecureSkipVerify bool) *ProxyBackend {
	b := ProxyBackend{
		outHostPort:        outHostPort,
		verbose:            verbose,
		insecureSkipVerify: insecureSkipVerify,
	}
	return &b
}

// SetVerbose allows changing logging options on-the-fly
func (bkd *ProxyBackend) SetVerbose(v bool) {
	bkd.verbose = v
}

func (bkd *ProxyBackend) logger(args ...interface{}) {
	if bkd.verbose {
		log.Println(args...)
	}
}

func (bkd *ProxyBackend) loggerAlways(args ...interface{}) {
	log.Println(args...)
}

// MakeSession returns a session for this client and backend
func (bkd *ProxyBackend) MakeSession(c *Client) Session {
	var s proxySession
	s.bkd = bkd    // just for logging
	s.upstream = c // keep record of the upstream Client connection
	return &s
}

// Init the backend. Here we establish the upstream connection
func (bkd ProxyBackend) Init() (Session, error) {
	bkd.logger("---Connecting upstream")
	c, err := Dial(bkd.outHostPort)
	if err != nil {
		bkd.loggerAlways("< Connection error", bkd.outHostPort, err.Error())
		return nil, err
	}
	bkd.logger("< Connection success", bkd.outHostPort)
	return bkd.MakeSession(c), nil
}

//-----------------------------------------------------------------------------
// Session handlers

// A Session is returned after successful login. Here hold information that needs to persist across message phases.
type proxySession struct {
	bkd      *ProxyBackend // The backend that created this session. Allows session methods to e.g. log
	upstream *Client       // the upstream client this backend is driving
}

// cmdTwiddle returns different flow markers depending on whether connection is secure (like Swaks does)
func cmdTwiddle(s *proxySession) string {
	if s.upstream != nil {
		if _, isTLS := s.upstream.TLSConnectionState(); isTLS {
			return "~>"
		}
	}
	return "->"
}

// respTwiddle returns different flow markers depending on whether connection is secure (like Swaks does)
func respTwiddle(s *proxySession) string {
	if s.upstream != nil {
		if _, isTLS := s.upstream.TLSConnectionState(); isTLS {
			return "\t<~"
		}
	}
	return "\t<-"
}

// Greet the upstream host and report capabilities back.
func (s *proxySession) Greet(helotype string) ([]string, int, string, error) {
	s.bkd.logger(cmdTwiddle(s), helotype)
	host, _, _ := net.SplitHostPort(s.bkd.outHostPort)
	if host == "" {
		host = "smtpproxy.localhost" // add dummy value in
	}
	code, msg, err := s.upstream.Hello(host)
	if err != nil {
		s.bkd.loggerAlways(respTwiddle(s), helotype, "error", err.Error())
		if code == 0 {
			// some errors don't show up in (code,msg) e.g. TLS cert errors, so map as a specific SMTP code/msg response
			code = 599
			msg = err.Error()
		}
		return nil, code, msg, err
	}
	s.bkd.logger(respTwiddle(s), helotype, "success")
	caps := s.upstream.Capabilities()
	s.bkd.logger("\tUpstream capabilities:", caps)
	return caps, code, msg, err
}

// StartTLS command
func (s *proxySession) StartTLS() (int, string, error) {
	host, _, _ := net.SplitHostPort(s.bkd.outHostPort)
	// Try the upstream server, it will report error if unsupported
	tlsconfig := &tls.Config{
		InsecureSkipVerify: s.bkd.insecureSkipVerify,
		ServerName:         host,
	}
	s.bkd.logger(cmdTwiddle(s), "STARTTLS")
	code, msg, err := s.upstream.StartTLS(tlsconfig)
	if err != nil {
		s.bkd.loggerAlways(respTwiddle(s), code, msg)
	} else {
		s.bkd.logger(respTwiddle(s), code, msg)
	}
	return code, msg, err
}

//Auth command backend handler
func (s *proxySession) Auth(expectcode int, cmd, arg string) (int, string, error) {
	return s.Passthru(expectcode, cmd, arg)
}

//Mail command backend handler
func (s *proxySession) Mail(expectcode int, cmd, arg string) (int, string, error) {
	return s.Passthru(expectcode, cmd, arg)
}

//Rcpt command backend handler
func (s *proxySession) Rcpt(expectcode int, cmd, arg string) (int, string, error) {
	return s.Passthru(expectcode, cmd, arg)
}

//Reset command backend handler
func (s *proxySession) Reset(expectcode int, cmd, arg string) (int, string, error) {
	return s.Passthru(expectcode, cmd, arg)
}

//Quit command backend handler
func (s *proxySession) Quit(expectcode int, cmd, arg string) (int, string, error) {
	return s.Passthru(expectcode, cmd, arg)
}

//Unknown command backend handler
func (s *proxySession) Unknown(expectcode int, cmd, arg string) (int, string, error) {
	return s.Passthru(expectcode, cmd, arg)
}

// Passthru a command to the upstream server, logging
func (s *proxySession) Passthru(expectcode int, cmd, arg string) (int, string, error) {
	s.bkd.logger(cmdTwiddle(s), cmd, arg)
	joined := cmd
	if arg != "" {
		joined = cmd + " " + arg
	}
	code, msg, err := s.upstream.MyCmd(expectcode, joined)
	if err != nil {
		s.bkd.loggerAlways(respTwiddle(s), cmd, code, msg, "error", err.Error())
		if code == 0 {
			// some errors don't show up in (code,msg) e.g. TLS cert errors, so map as a specific SMTP code/msg response
			code = 599
			msg = err.Error()
		}
	} else {
		s.bkd.logger(respTwiddle(s), code, msg)
	}
	return code, msg, err
}

// DataCommand pass upstream, returning a place to write the data AND the usual responses
func (s *proxySession) DataCommand() (io.WriteCloser, int, string, error) {
	s.bkd.logger(cmdTwiddle(s), "DATA")
	w, code, msg, err := s.upstream.Data()
	if err != nil {
		s.bkd.loggerAlways(respTwiddle(s), "DATA error", err.Error())
	}
	return w, code, msg, err
}

// Data body (dot delimited) pass upstream, returning the usual responses
func (s *proxySession) Data(r io.Reader, w io.WriteCloser) (int, string, error) {
	// Send the data upstream
	count, err := io.Copy(w, r)
	if err != nil {
		msg := "DATA io.Copy error"
		s.bkd.loggerAlways(respTwiddle(s), msg, err.Error())
		return 0, msg, err
	}
	err = w.Close() // Need to close the data phase - then we should have response from upstream
	code := s.upstream.DataResponseCode
	msg := s.upstream.DataResponseMsg
	if err != nil {
		s.bkd.loggerAlways(respTwiddle(s), "DATA Close error", err, ", bytes written =", count)
		return 0, msg, err
	}
	if s.bkd.verbose {
		s.bkd.logger(respTwiddle(s), "DATA accepted, bytes written =", count)
	} else {
		// Short-form logging - one line per message - used when "verbose" not set
		log.Printf("Message DATA upstream,%d,%d,%s\n", count, code, msg)
	}
	return code, msg, err
}
