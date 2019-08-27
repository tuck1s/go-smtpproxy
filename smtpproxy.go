// Package smtpproxy is based heavily on https://github.com/emersion/go-smtp, with increased transparency of response codes and no sasl dependency.
package smtpproxy

import (
	"errors"
	"strings"
)

// validateLine checks to see if a line has CR or LF as per RFC 5321
func validateLine(line string) error {
	if strings.ContainsAny(line, "\n\r") {
		return errors.New("smtp: A line must not contain CR or LF")
	}
	return nil
}
