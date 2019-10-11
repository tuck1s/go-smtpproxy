//Package smtpproxy is based heavily on https://github.com/emersion/go-smtp, with increased transparency of response codes and no sasl dependency.
package smtpproxy

import (
	"bufio"
	"encoding/base64"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
)

const smtpCRLF = "\r\n"

// Processing of email body via IO stream functions

/* If you just want to pass through the entire mail headers and body, you can just use
   the following alernative:

func MailCopy(dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}
*/

// MailCopy transfers the mail body from downstream (client) to upstream (server)
// The writer will be closed by the parent function, no need to close it here.
func MailCopy(dst io.Writer, src io.Reader) (int, error) {
	bytesWritten := 0
	message, err := mail.ReadMessage(bufio.NewReader(src))
	if err != nil {
		return bytesWritten, err
	}

	// Pass through headers. The m.Header map does not preserve order, but that should not matter.
	for hdrType, hdrList := range message.Header {
		for _, hdrVal := range hdrList {
			hdrLine := hdrType + ": " + hdrVal + smtpCRLF
			bw, err := io.WriteString(dst, hdrLine)
			bytesWritten += bw
			if err != nil {
				return bytesWritten, err
			}
		}
	}
	// Blank line denotes end of headers
	bw, err := io.WriteString(dst, smtpCRLF)
	bytesWritten += bw
	if err != nil {
		return bytesWritten, err
	}

	// Handle the message body
	bw, err = handleMessageBody(dst, message.Header, message.Body)
	bytesWritten += bw
	return bytesWritten, err
}

// handleMessageBody copies the mail message from msg to dst, with awareness of MIME parts.
// This is probably a naive implementation when it comes to complex multi-part messages and
// differing encodings.
func handleMessageBody(dst io.Writer, msgHeader mail.Header, msgBody io.Reader) (int, error) {
	cType := msgHeader.Get("Content-Type")
	cte := msgHeader.Get("Content-Transfer-Encoding")
	return handleMessagePart(dst, msgBody, cType, cte)
}

// handleMessagePart walks the MIME structure, and may be called recursively. The incoming
// content type and cte (content transfer encoding) are passed separately
func handleMessagePart(dst io.Writer, part io.Reader, cType string, cte string) (int, error) {
	bytesWritten := 0
	// Check what MIME media type we have.
	mediaType, params, err := mime.ParseMediaType(cType)
	if err != nil {
		return bytesWritten, err
	}
	if strings.HasPrefix(mediaType, "text/html") {
		// Insert decoder into incoming part, and encoder into dst. Quoted-Printable is automatically handled
		// by the reader, no need to handle here: https://golang.org/src/mime/multipart/multipart.go?s=825:1710#L25
		if cte == "base64" {
			part = base64.NewDecoder(base64.StdEncoding, part)
			// pass output through base64 encoding -> line splitter
			var ls linesplitter
			lsWriter := ls.NewWriter(76, []byte("\r\n"), dst)
			dst = base64.NewEncoder(base64.StdEncoding, lsWriter)
		} else {
			if !(cte == "" || cte == "7bit" || cte == "8bit") {
				log.Println("Warning: don't know how to handle Content-Type-Encoding", cte)
			}
		}
		bytesWritten, err = handleHTMLPart(dst, part)
	} else {
		if strings.HasPrefix(mediaType, "multipart/") {
			mr := multipart.NewReader(part, params["boundary"])
			bytesWritten, err = handleMultiPart(dst, mr, params["boundary"])
		} else {
			if strings.HasPrefix(mediaType, "message/rfc822") {
				bytesWritten, err = MailCopy(dst, part)
			} else {
				// Everything else such as text/plain, image/gif etc pass through
				bytesWritten, err = handlePlainPart(dst, part)
			}
		}
	}
	return bytesWritten, err
}

// Transfer through a plain MIME part
func handlePlainPart(dst io.Writer, src io.Reader) (int, error) {
	written, err := io.Copy(dst, src) // Passthrough
	return int(written), err
}

// Transfer through an html MIME part, wrapping links etc
func handleHTMLPart(dst io.Writer, src io.Reader) (int, error) {
	written, err := io.Copy(dst, src) // Passthrough
	return int(written), err
}

// Transfer through a multipart message, handling recursively as needed
func handleMultiPart(dst io.Writer, mr *multipart.Reader, bound string) (int, error) {
	bytesWritten := 0
	var err error
	// Insert the
	bw, err := io.WriteString(dst, "This is a multi-part message in MIME format."+smtpCRLF)
	bytesWritten += bw
	// Create a part writer with the current boundary and header properties
	pWrt := multipart.NewWriter(dst)
	pWrt.SetBoundary(bound)
	for {
		p, err := mr.NextPart()
		if err != nil {
			if err == io.EOF {
				err = nil // Usual termination
				break
			}
			return bytesWritten, err // Unexpected error
		}
		pWrt2, err := pWrt.CreatePart(p.Header)
		if err != nil {
			return bytesWritten, err
		}
		cType := p.Header.Get("Content-Type")
		cte := p.Header.Get("Content-Transfer-Encoding")
		bw, err := handleMessagePart(pWrt2, p, cType, cte)
		bytesWritten += bw
		if err != nil {
			return bytesWritten, err
		}
	}
	pWrt.Close() // Put the boundary in
	return bytesWritten, err
}
