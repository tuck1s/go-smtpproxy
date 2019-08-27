// Package smtpproxy is based heavily on https://github.com/emersion/go-smtp, with increased transparency of response codes and no sasl dependency.
package smtpproxy

import (
	"io"
)

// EnhancedCode as per https://tools.ietf.org/html/rfc3463
type EnhancedCode [3]int

// SMTPError specifies the error code and message that needs to be returned to the client
type SMTPError struct {
	Code         int
	EnhancedCode EnhancedCode
	Message      string
}

// NoEnhancedCode is used to indicate that enhanced error code should not be
// included in response.
//
// Note that RFC 2034 requires an enhanced code to be included in all 2xx, 4xx
// and 5xx responses. This constant is exported for use by extensions, you
// should probably use EnhancedCodeNotSet instead.
var NoEnhancedCode = EnhancedCode{-1, -1, -1}

// EnhancedCodeNotSet is a nil value of EnhancedCode field in SMTPError, used
// to indicate that backend failed to provide enhanced status code. X.0.0 will
// be used (X is derived from error code).
var EnhancedCodeNotSet = EnhancedCode{0, 0, 0}

func (err *SMTPError) Error() string {
	return err.Message
}

type dataReader struct {
	r io.Reader
}

func newDataReader(c *Conn) io.Reader {
	dr := &dataReader{
		r: c.text.DotReader(),
	}
	return dr
}

func (r *dataReader) Read(b []byte) (n int, err error) {
	n, err = r.r.Read(b)
	return
}
