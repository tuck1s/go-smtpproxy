// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package smtpproxy is based heavily on https://github.com/emersion/go-smtp, with increased transparency of response codes and no sasl dependency.
package smtpproxy

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/textproto"
	"sort"
	"strings"
)

// A Client represents a client connection to an SMTP server. Stripped out unused functionality for proxy
type Client struct {
	Text             *textproto.Conn // Text is the textproto.Conn used by the Client. It is exported to allow for clients to add extensions.
	conn             net.Conn        // keep a reference to the connection so it can be used to create a TLS connection later
	tls              bool            // whether the Client is using TLS
	serverName       string
	ext              map[string]string // map of supported extensions
	localName        string            // the name to use in HELO/EHLO/LHLO
	didHello         bool              // whether we've said HELO/EHLO/LHLO
	helloMsg         string            // the error message from the hello
	helloCode        int               // the error code from the hello
	helloErr         error             // Error form of the above
	DataResponseCode int               // proxy error reporting for data phase (as writeCloser can only return "error" class)
	DataResponseMsg  string
}

// Dial returns a new Client connected to an SMTP server at addr.
// The addr must include a port, as in "mail.example.com:smtp".
func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	return NewClient(conn, host)
}

// DialTLS returns a new Client connected to an SMTP server via TLS at addr.
// The addr must include a port, as in "mail.example.com:smtps".
func DialTLS(addr string, tlsConfig *tls.Config) (*Client, error) {
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	return NewClient(conn, host)
}

// NewClient returns a new Client using an existing connection and host as a
// server name to be used when authenticating.
func NewClient(conn net.Conn, host string) (*Client, error) {
	text := textproto.NewConn(conn)
	_, _, err := text.ReadResponse(220)
	if err != nil {
		text.Close()
		return nil, err
	}
	_, isTLS := conn.(*tls.Conn)
	c := &Client{Text: text, conn: conn, serverName: host, localName: "localhost", tls: isTLS}
	return c, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.Text.Close()
}

// hello runs a hello exchange if needed.
func (c *Client) hello() (int, string, error) {
	if !c.didHello {
		c.didHello = true
		// Try Extended hello first
		c.helloCode, c.helloMsg, c.helloErr = c.ehlo()
		if c.helloErr != nil {
			// Didn't succeed, try a basic hello
			c.helloCode, c.helloMsg, c.helloErr = c.helo()
		}
	}
	return c.helloCode, c.helloMsg, c.helloErr
}

// Hello sends a HELO or EHLO to the server as the given host name.
// Calling this method is only necessary if the client needs control
// over the host name used. The client will introduce itself as "localhost"
// automatically otherwise. If Hello is called, it must be called before
// any of the other methods.
//
// This version does not specifically check for repeat calling of (E)HELO,
// we'll let the upstream server tell us that
func (c *Client) Hello(localName string) (int, string, error) {
	if err := validateLine(localName); err != nil {
		return 421, err.Error(), err
	}
	c.localName = localName
	return c.hello()
}

// cmd is a convenience function that sends a command and returns the response
func (c *Client) cmd(expectCode int, format string, args ...interface{}) (int, string, error) {
	id, err := c.Text.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	c.Text.StartResponse(id)
	defer c.Text.EndResponse(id)
	code, msg, err := c.Text.ReadResponse(expectCode)
	return code, msg, err
}

// MyCmd - is a wrapper for underlying method
func (c *Client) MyCmd(expectCode int, format string, args ...interface{}) (int, string, error) {
	return c.cmd(expectCode, format, args...)
}

// helo sends the HELO greeting to the server. It should be used only when the
// server does not support ehlo.
func (c *Client) helo() (int, string, error) {
	c.ext = nil
	return c.cmd(250, "HELO %s", c.localName)
}

// ehlo sends the EHLO (extended hello) greeting to the server. It
// should be the preferred greeting for servers that support it.
// Now returns code, msg, error for transparency.
func (c *Client) ehlo() (int, string, error) {
	cmd := "EHLO"
	code, msg, err := c.cmd(250, "%s %s", cmd, c.localName)
	if err == nil {
		ext := make(map[string]string)
		extList := strings.Split(msg, "\n")
		if len(extList) > 1 {
			extList = extList[1:]
			for _, line := range extList {
				args := strings.SplitN(line, " ", 2)
				if len(args) > 1 {
					ext[args[0]] = args[1]
				} else {
					ext[args[0]] = ""
				}
			}
		}
		c.ext = ext
	}
	return code, msg, err
}

// StartTLS sends the STARTTLS command and encrypts all further communication.
// This is stripped down to not attempt (E)HLOs first.
func (c *Client) StartTLS(config *tls.Config) (int, string, error) {
	code, msg, err := c.cmd(220, "STARTTLS")
	if err != nil {
		return code, msg, err
	}
	if config == nil {
		config = &tls.Config{}
	}
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument
		config = config.Clone()
		config.ServerName = c.serverName
	}
	if testHookStartTLS != nil {
		testHookStartTLS(config)
	}
	c.conn = tls.Client(c.conn, config)
	c.Text = textproto.NewConn(c.conn)
	c.tls = true
	c.didHello = false // Important to pass internal checks before next EHLO
	return code, msg, err
}

// TLSConnectionState returns the client's TLS connection state.
// The return values are their zero values if StartTLS did
// not succeed.
func (c *Client) TLSConnectionState() (state tls.ConnectionState, ok bool) {
	tc, ok := c.conn.(*tls.Conn)
	if !ok {
		return
	}
	return tc.ConnectionState(), true
}

type dataCloser struct {
	c *Client
	io.WriteCloser
}

// Data closer
// Conforms to the WriteCloser spec (returning only error)
func (d *dataCloser) Close() error {
	d.WriteCloser.Close()
	// Pass the extended response info back via Client structure.
	code, msg, err := d.c.Text.ReadResponse(250)
	d.c.DataResponseCode = code
	d.c.DataResponseMsg = msg
	return err
}

// Data issues a DATA command to the server and returns a writer that
// can be used to write the mail headers and body. The caller should
// close the writer before calling any more methods on c. A call to
// Data must be preceded by one or more calls to Rcpt.
func (c *Client) Data() (io.WriteCloser, int, string, error) {
	code, msg, err := c.cmd(354, "DATA")
	if err != nil {
		return nil, code, msg, err
	}
	return &dataCloser{c, c.Text.DotWriter()}, code, msg, err
}

var testHookStartTLS func(*tls.Config) // nil, except for tests

// Extension reports whether an extension is support by the server.
// The extension name is case-insensitive. If the extension is supported,
// Extension also returns a string that contains any parameters the
// server specifies for the extension.
func (c *Client) Extension(ext string) (bool, string) {
	if c.ext == nil {
		return false, ""
	}
	ext = strings.ToUpper(ext)
	param, ok := c.ext[ext]
	return ok, param
}

// Capabilities reports all supported by the client, as a slice of strings
// Second param indicates is STARTTLS is available
// Return in lexically sorted order, so we get the same results each time
func (c *Client) Capabilities() []string {
	caps := []string{}
	for cap, param := range c.ext {
		cap = strings.ToUpper(cap)
		param = strings.ToUpper(param)
		if param != "" {
			cap += " " + param
		}
		caps = append(caps, cap)
	}
	sort.Strings(caps)
	return caps
}

// validateLine checks to see if a line has CR or LF as per RFC 5321
func validateLine(line string) error {
	if strings.ContainsAny(line, "\n\r") {
		return errors.New("smtp: A line must not contain CR or LF")
	}
	return nil
}
