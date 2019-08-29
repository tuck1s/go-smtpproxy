//Package smtpproxy is based heavily on https://github.com/emersion/go-smtp, with increased transparency of response codes and no sasl dependency.
package smtpproxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/textproto"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// ConnectionState gives useful info about the incoming connection, including the TLS status
type ConnectionState struct {
	Hostname   string
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	TLS        tls.ConnectionState
}

// Conn is the incoming connection
type Conn struct {
	conn      net.Conn
	text      *textproto.Conn
	server    *Server
	helo      string
	nbrErrors int
	session   Session
	locker    sync.Mutex
}

func newConn(c net.Conn, s *Server) *Conn {
	sc := &Conn{
		server: s,
		conn:   c,
	}

	sc.init()
	return sc
}

func (c *Conn) init() {
	var rwc io.ReadWriteCloser = c.conn
	if c.server.Debug != nil {
		rwc = struct {
			io.Reader
			io.Writer
			io.Closer
		}{
			io.TeeReader(c.conn, c.server.Debug),
			io.MultiWriter(c.conn, c.server.Debug),
			c.conn,
		}
	}
	c.text = textproto.NewConn(rwc)
}

// Commands are dispatched to the appropriate handler functions.
func (c *Conn) handle(cmd string, arg string) {
	// If panic happens during command handling - send 421 response
	// and close connection.
	defer func() {
		if err := recover(); err != nil {
			c.WriteResponse(421, EnhancedCode{4, 0, 0}, "Internal server error")
			c.Close()

			stack := debug.Stack()
			c.server.ErrorLog.Printf("panic serving %v: %v\n%s", c.State().RemoteAddr, err, stack)
		}
	}()

	if cmd == "" {
		c.WriteResponse(500, EnhancedCode{5, 5, 2}, "Speak up")
		return
	}

	cmd = strings.ToUpper(cmd)
	switch cmd {
	case "HELO", "EHLO":
		c.handleHelo(cmd, arg) // Pass in cmd as could be either
	case "AUTH":
		c.handleAuth(arg)
	case "MAIL":
		c.handleMail(arg)
	case "RCPT":
		c.handleRcpt(arg)
	case "RSET": // Reset session
		c.handleReset()
	case "DATA":
		c.handleData(arg)
	case "STARTTLS":
		c.handleStartTLS()
	case "QUIT":
		c.handleQuit()
		c.Close()
	default:
		c.handleUnknown(cmd, arg) // Rather than rejecting this here, use the upstream server's responses
	}
}

// Server name of this connection
func (c *Conn) Server() *Server {
	return c.server
}

// Session associated with this connection
func (c *Conn) Session() Session {
	c.locker.Lock()
	defer c.locker.Unlock()
	return c.session
}

// SetSession - setting the user resets any message being generated
func (c *Conn) SetSession(session Session) {
	c.locker.Lock()
	defer c.locker.Unlock()
	c.session = session
}

// Close this connection
func (c *Conn) Close() error {
	return c.conn.Close()
}

// TLSConnectionState returns the connection's TLS connection state.
// Zero values are returned if the connection doesn't use TLS.
func (c *Conn) TLSConnectionState() (state tls.ConnectionState, ok bool) {
	tc, ok := c.conn.(*tls.Conn)
	if !ok {
		return
	}
	return tc.ConnectionState(), true
}

// State of this connection
func (c *Conn) State() ConnectionState {
	state := ConnectionState{}
	tlsState, ok := c.TLSConnectionState()
	if ok {
		state.TLS = tlsState
	}

	state.Hostname = c.helo
	state.LocalAddr = c.conn.LocalAddr()
	state.RemoteAddr = c.conn.RemoteAddr()

	return state
}

func code2xxSuccess(code int) bool {
	return (code >= 200) && (code <= 299)
}

func code5xxPermFail(code int) bool {
	return (code >= 500) && (code <= 559)
}

// Change the downstream (client) connection, and upstream connection (via backend) to TLS
func (c *Conn) handleStartTLS() {
	if _, isTLS := c.TLSConnectionState(); isTLS {
		c.WriteResponse(502, EnhancedCode{5, 5, 1}, "Already running in TLS")
		return
	}

	// Change upstream to TLS. If this fails, don't continue with the downstream change
	code, msg, err := c.Session().StartTLS()
	c.WriteResponse(code, NoEnhancedCode, msg)
	if err != nil {
		return
	}

	// Change downstream to TLS
	var tlsConn *tls.Conn
	tlsConn = tls.Server(c.conn, c.server.TLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		c.WriteResponse(550, EnhancedCode{5, 0, 0}, "Handshake error")
	}
	c.conn = tlsConn
	c.init()
}

// WriteResponse back to the incoming connection.
// If you do not want an enhanced code added, pass in value NoEnhancedCode.
func (c *Conn) WriteResponse(code int, enhCode EnhancedCode, text ...string) {
	// TODO: error handling
	if c.server.WriteTimeout != 0 {
		c.conn.SetWriteDeadline(time.Now().Add(c.server.WriteTimeout))
	}

	// All responses must include an enhanced code, if it is missing - use
	// a generic code X.0.0.
	if enhCode == EnhancedCodeNotSet {
		cat := code / 100
		switch cat {
		case 2, 4, 5:
			enhCode = EnhancedCode{cat, 0, 0}
		default:
			enhCode = NoEnhancedCode
		}
	}

	for i := 0; i < len(text)-1; i++ {
		c.text.PrintfLine("%v-%v", code, text[i])
	}
	if enhCode == NoEnhancedCode {
		c.text.PrintfLine("%v %v", code, text[len(text)-1])
	} else {
		c.text.PrintfLine("%v %v.%v.%v %v", code, enhCode[0], enhCode[1], enhCode[2], text[len(text)-1])
	}
}

// ReadLine reads a line of input from the incoming connection
func (c *Conn) ReadLine() (string, error) {
	if c.server.ReadTimeout != 0 {
		if err := c.conn.SetReadDeadline(time.Now().Add(c.server.ReadTimeout)); err != nil {
			return "", err
		}
	}
	return c.text.ReadLine()
}

func (c *Conn) greet() {
	c.WriteResponse(220, NoEnhancedCode, fmt.Sprintf("%v ESMTP Service Ready", c.server.Domain))
}

//-----------------------------------------------------------------------------
// Transparent incoming command handlers
//-----------------------------------------------------------------------------

// handleHelo - HELO / EHLO received
func (c *Conn) handleHelo(cmd, arg string) {
	domain, err := parseHelloArgument(arg)
	if err != nil {
		c.WriteResponse(501, EnhancedCode{5, 5, 2}, "Domain/address argument required")
		return
	}
	c.helo = domain

	// If no existing session, establish one
	if c.session == (interface{})(nil) {
		s, err := c.server.Backend.Init()
		if err != nil {
			c.WriteResponse(421, EnhancedCode{4, 0, 0}, "Internal server error")
			return
		}
		c.session = s
	}
	// Pass greeting to the backend, updating our server capabilities to mirror them
	upstreamCaps, code, msg, err := c.Session().Greet(cmd)
	if err != nil {
		c.WriteResponse(code, EnhancedCode{4, 0, 0}, msg)
		return
	}
	if len(upstreamCaps) > 0 {
		c.server.caps = []string{}
		for _, i := range upstreamCaps {
			if i == "STARTTLS" {
				// Offer STARTTLS to the downstream client, but only if our TLS is configured
				// and downstream not already in TLS
				if _, isTLS := c.TLSConnectionState(); c.server.TLSConfig == nil || isTLS {
					continue
				}
			}
			c.server.caps = append(c.server.caps, i)
		}
	}
	if cmd == "HELO" {
		c.WriteResponse(250, EnhancedCode{2, 0, 0}, fmt.Sprintf("Hello %s", domain))
	}
	args := []string{"Hello " + domain}
	args = append(args, c.server.caps...)
	c.WriteResponse(250, NoEnhancedCode, args...)
}

func (c *Conn) handleAuth(arg string) {
	c.handlePassthru("AUTH", arg, c.Session().Auth)
}

func (c *Conn) handleMail(arg string) {
	c.handlePassthru("MAIL", arg, c.Session().Mail)
}

func (c *Conn) handleRcpt(arg string) {
	c.handlePassthru("RCPT", arg, c.Session().Rcpt)
}

func (c *Conn) handleReset() {
	c.handlePassthru("RSET", "", c.Session().Reset)
}

func (c *Conn) handleQuit() {
	c.handlePassthru("QUIT", "", c.Session().Quit)
}

func (c *Conn) handleUnknown(cmd, arg string) {
	c.handlePassthru(cmd, arg, c.Session().Unknown)
}

// handlePassthru - pass the command and args through to the specified backend session function, handling responses transparently until success or permanent failure.
func (c *Conn) handlePassthru(cmd, arg string, fn SessionFunc) {
	code, msg, err := fn(0, cmd, arg)
	c.WriteResponse(code, NoEnhancedCode, msg)
	if err != nil {
		return
	}
	for {
		encoded, err := c.ReadLine()
		if err != nil {
			return
		}
		code, msg, err := fn(0, encoded, "")
		c.WriteResponse(code, NoEnhancedCode, msg)
		if code2xxSuccess(code) || code5xxPermFail(code) {
			break
		}
	}
}

// handleData
func (c *Conn) handleData(arg string) {
	w, code, msg, _ := c.Session().DataCommand()
	// Enhanced code is at the beginning of msg, no need to add anything
	c.WriteResponse(code, NoEnhancedCode, msg)

	r := newDataReader(c)
	code, msg, _ = c.Session().Data(r, w)
	io.Copy(ioutil.Discard, r) // Make sure all the incoming data has been consumed
	c.WriteResponse(code, NoEnhancedCode, msg)
}
