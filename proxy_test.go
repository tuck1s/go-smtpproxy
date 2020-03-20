// smtpproxy_test is a simplified (non-wrapping) version of https://github.com/tuck1s/sparkypmtatracking/blob/master/wrap_smtp.go
package smtpproxy_test

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	smtpproxy "github.com/tuck1s/go-smtpproxy"
)

// localhostCert is a PEM-encoded TLS cert.pem, made for domain test.example.com
//		openssl req -nodes -new -x509 -keyout key.pem -out cert.pem
var localhostCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIDvDCCAqQCCQDG9Km7C037rDANBgkqhkiG9w0BAQsFADCBnzELMAkGA1UEBhMC
dWsxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMRIwEAYDVQQKDAlT
cGFya1Bvc3QxHjAcBgNVBAsMFU1lc3NhZ2luZyBFbmdpbmVlcmluZzEZMBcGA1UE
AwwQdGVzdC5leGFtcGxlLmNvbTEfMB0GCSqGSIb3DQEJARYQdGVzdEBleGFtcGxl
LmNvbTAeFw0yMDAyMDYyMTIyMDNaFw0yMDAzMDcyMTIyMDNaMIGfMQswCQYDVQQG
EwJ1azEPMA0GA1UECAwGTG9uZG9uMQ8wDQYDVQQHDAZMb25kb24xEjAQBgNVBAoM
CVNwYXJrUG9zdDEeMBwGA1UECwwVTWVzc2FnaW5nIEVuZ2luZWVyaW5nMRkwFwYD
VQQDDBB0ZXN0LmV4YW1wbGUuY29tMR8wHQYJKoZIhvcNAQkBFhB0ZXN0QGV4YW1w
bGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4yGJRYAI6xtQ
ZPRxIWU+ZjlKo66LFvfr2VrWd30m8dflB0CNMkaaEMGt29jwLvzkP/mfn5dYVw3E
dFJ2yBGR3wDy02ssmBVaOYkbYxgxeFa9jIgBLJONA3HIJRjn91/3lSCxDo6cE7l+
ufhf8pc78YBZvhbC50kBajQtYaENcca9asj5cCRHS44hL7sCzN4kGETkg1jYtocT
CMjJIgQ3dJool7M9MEAafWiFnIcO76O/jxewggLgOkfj7i9Y1iP6aWScEq6nNkW7
8xFNqFafnK7W85TzkpfRIN/ntpEwgPcUHG4b4AWpXWR6q+1do25WgaWvt/od45KN
aIo1kylOwQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCODjmvtqracVuOjsRp7841
7glTqDQeXIUr3X7UvDTyvl70oeGeqnaEs3hO79T15gz0pKlKbYlB3B4v7fldmrLU
mu0uQ7W112NBXYt71wpwuVQWdWSRi9rcAyvuf2nHLZ9fVjczxbCAi+QUFVY+ERoO
CfngvPkPQvLB7VT/oKXKN+j8bXBJ+fYLA6fX4kzpuwx9hf+ay9x+JpPAB/dPEDjB
KsbnfZsIPeuERAlWoSX/c9ggXPXzh95oZz6RhicmtPy3z2ZYJL4BsgEtbazOc6aO
7c/t3Z1FScoSgCql4MXv9kLVL2LNGTWja89pnFnRaobagQ7XB0MEUotrM0ow18SM
-----END CERTIFICATE-----`)

// corresponding private key.pem
var localhostKey = []byte(`
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDjIYlFgAjrG1Bk
9HEhZT5mOUqjrosW9+vZWtZ3fSbx1+UHQI0yRpoQwa3b2PAu/OQ/+Z+fl1hXDcR0
UnbIEZHfAPLTayyYFVo5iRtjGDF4Vr2MiAEsk40DccglGOf3X/eVILEOjpwTuX65
+F/ylzvxgFm+FsLnSQFqNC1hoQ1xxr1qyPlwJEdLjiEvuwLM3iQYROSDWNi2hxMI
yMkiBDd0miiXsz0wQBp9aIWchw7vo7+PF7CCAuA6R+PuL1jWI/ppZJwSrqc2Rbvz
EU2oVp+crtbzlPOSl9Eg3+e2kTCA9xQcbhvgBaldZHqr7V2jblaBpa+3+h3jko1o
ijWTKU7BAgMBAAECggEAHbtvH8Tx5ezuajjBcnCxaWpIhgK8PGZ53jsQ5hVg+rmb
RobBtPofAuCHpMbSMiRysJk5twd1zfeEZwHAgNIj+UBDiT93V/U7mVqEVkV9fFZG
e9X16WLrS68iVxDalLxgSYo9Az3R2pcmqquDy9rWQvfdR4/tNZ+N6twnsKcHfoQZ
Z2lIZrmbR1ZqAEK7T7J5rm2WR+430cuTGEl/X39iIVimwo9QZIs6VikYRYyJoS8u
8VtNsPY7lhnoPctMyErzWeslZXThFmuA5xqtEgFai51dhiJd/+iLkKtbHkfiLeF9
ej+b40LnPT/rnYkBkyyvp2vVXnEUxPEAOzImzE8bQQKBgQD8TP5/Lg/lGK6CcSjD
XG3/w0sfFQtC+oN3I/iFv/tgTQQRF/el7uF79si31TicZPDJgKbnuOGkOdSEyl4u
Mg4yEwX4e+Grb13aENZb5p+fyN91P0jD+4lzLm6k4RaSN/EkDEe9LSn+wIUedO/A
iG4S79EPyYo8pWdNUBO4ZQx3uQKBgQDmdhFiPIdynNDWy1IxhVUnrUuDMyUKFNZB
Rd3KgABgfOBcdB9oeFEijsH86DI2kjHO+rVyCC9F1s8H5VC3eDKtuUaExqBixtu6
TB3BXX+ZapiH8dThXtIa8vteTD5MHLC7pDcESVGzJH3vhdcOhek7es8j78vXZRZq
q/teONQDSQKBgGBh2WckZZYTU7cpG3VmPe9S38PD+kVgBhDhgPM3YARt53vQOB7/
nswIfq0bm0DDnuibaSdkjW57WSBRXqEvJhUjB0jhqlgfdy7y97Cr7ZbQ2eykfFvC
H8QMnOAHzOOW01v+BPnT4xMa4L+91Eks1UAOtULerxxz4365dI8gqx6hAoGAT5iZ
um8jbN9idb01fysI1TJSMVc5xLibo2GpD6aT+r9Gkkf9DQz5INFjiKD9rsFheJY4
ktDm2t0tFhIKhcN65WtnQraDcHo0K6zcXguX5Xnegp1wpAIm2O3xCYmVvp3uIHDA
G7fjAtdos5BrTXXMryFkZ4oLwjIEwwTxRYKlHxkCgYEAi3lkuZl5soQT3d2tkhmc
F6WuDkR4nHxalD05oYtpjAPGpJqwJsyChFAyuUm7kn3qeX0l/Ll4GT6V4KsGQyin
g3Iip0KPOiY+ndAxffTAAiyjFHB7UVe5vfe8NAIU9eBDT8Ibbi2ay9IhQaRABWOc
KnpOfyDnCZbjNekskQaOqiE=
-----END PRIVATE KEY-----`)

const (
	Init = iota
	Greeted
	AskedUsername
	AskedPassword
	GotPassword
)

// Test design is to make a "sandwich" with wrapper in the middle.
//      test client <--> wrapper <--> mock SMTP server (Backend, Session)
// The mock SMTP server returns realistic looking response codes etc
type mockBackend struct {
	mockReply chan []byte
}

// A Session is returned after successful login. Here hold information that needs to persist across message phases.
type mockSession struct {
	MockState int
	bkd       *mockBackend
}

// mockSMTPServer should be invoked as a goroutine to allow tests to continue
func mockSMTPServer(t *testing.T, addr string, mockReply chan []byte) {
	mockbe := mockBackend{
		mockReply: mockReply,
	}
	s := smtpproxy.NewServer(&mockbe)
	s.Addr = addr
	s.ReadTimeout = 60 * time.Second // changeme?
	s.WriteTimeout = 60 * time.Second
	if err := s.ServeTLS(localhostCert, localhostKey); err != nil {
		t.Fatal(err)
	}

	// Begin serving requests
	t.Log("Upstream mock SMTP server listening on", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		t.Fatal(err)
	}
}

// Init the backend. This does not need to do much.
func (bkd *mockBackend) Init() (smtpproxy.Session, error) {
	var s mockSession
	s.MockState = Init
	s.bkd = bkd
	return &s, nil
}

// Greet the upstream host and report capabilities back.
func (s *mockSession) Greet(helotype string) ([]string, int, string, error) {
	s.MockState = Greeted
	caps := []string{"8BITMIME", "STARTTLS", "ENHANCEDSTATUSCODES", "AUTH LOGIN PLAIN", "SMTPUTF8"}
	return caps, 220, "", nil
}

// StartTLS command
func (s *mockSession) StartTLS() (int, string, error) {
	return 220, "", nil
}

const mockMsg = "2.0.0 mock server accepts all"

//Auth command mock backend handler - naive, handles only AUTH LOGIN PLAIN
func (s *mockSession) Auth(expectcode int, cmd, arg string) (int, string, error) {
	var code int
	var msg string
	switch s.MockState {
	case Init:
	case Greeted:
		if arg == "LOGIN" {
			code = 334
			msg = base64.StdEncoding.EncodeToString([]byte("Username:"))
			s.MockState = AskedUsername
		} else if strings.HasPrefix(arg, "PLAIN") {
			code = 235
			msg = mockMsg
			s.MockState = GotPassword
		}
	case AskedUsername:
		code = 334
		msg = base64.StdEncoding.EncodeToString([]byte("Password:"))
		s.MockState = AskedPassword
	case AskedPassword:
		code = 235
		msg = mockMsg
		s.MockState = GotPassword
	}
	return code, msg, nil
}

//Mail command mock backend handler
func (s *mockSession) Mail(expectcode int, cmd, arg string) (int, string, error) {
	return 250, mockMsg, nil
}

//Rcpt command mock backend handler
func (s *mockSession) Rcpt(expectcode int, cmd, arg string) (int, string, error) {
	return 250, mockMsg, nil
}

//Reset command mock backend handler
func (s *mockSession) Reset(expectcode int, cmd, arg string) (int, string, error) {
	s.MockState = Init
	return 250, "2.0.0 mock reset", nil
}

//Quit command mock backend handler
func (s *mockSession) Quit(expectcode int, cmd, arg string) (int, string, error) {
	s.MockState = Init
	return 221, "2.3.0 mock says bye", nil
}

//Unknown command mock backend handler
func (s *mockSession) Unknown(expectcode int, cmd, arg string) (int, string, error) {
	return 500, "mock does not recognize this command", nil
}

type myWriteCloser struct {
	io.Writer
}

func (myWriteCloser) Close() error {
	return nil
}

// DataCommand pass upstream, returning a place to write the data AND the usual responses
// If you want to see the mail contents, replace Discard with os.Stdout
func (s *mockSession) DataCommand() (io.WriteCloser, int, string, error) {
	return myWriteCloser{Writer: ioutil.Discard}, 354, `3.0.0 mock says continue.  finished with "\r\n.\r\n"`, nil
}

// Data body (dot delimited) pass upstream, returning the usual responses.
// Also emit a copy back in the test harness response channel, if present
func (s *mockSession) Data(r io.Reader, w io.WriteCloser) (int, string, error) {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, r)
	resp := buf.Bytes()    // get the whole received mail body
	_, err = w.Write(resp) // copy through to the writer
	if s.bkd.mockReply != nil {
		s.bkd.mockReply <- resp
	}
	return 250, "2.0.0 OK mock got your dot", err
}

//-----------------------------------------------------------------------------
// Start proxy server

func startProxy(t *testing.T, s *smtpproxy.Server) {
	t.Log("Proxy (unit under test) listening on", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		t.Fatal(err)
	}
}

// tlsClientConfig is built from the passed in cert, privkey. InsecureSkipVerify allows self-signed certs to work
func tlsClientConfig(cert []byte, privkey []byte) (*tls.Config, error) {
	cer, err := tls.X509KeyPair(cert, privkey)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	config.InsecureSkipVerify = true
	return config, nil
}

//-----------------------------------------------------------------------------
// proxy tests

const inHostPort = "localhost:5580" // need to specifically have keyword localhost in here for c.Auth to accept nonsecure connections
const outHostPort = ":5581"
const downstreamDebug = "debug_proxy_test2.log"

func TestProxy(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	verboseOpt := true
	insecureSkipVerify := true
	// Logging of downstream (client to proxy server) commands and responses
	dbgFile, err := smtpproxy.DownstreamDebug(downstreamDebug)
	if err != nil {
		log.Fatal(err)
	}
	_ = dbgFile

	s, be, err := smtpproxy.CreateProxy(inHostPort, outHostPort, verboseOpt, localhostCert, localhostKey, insecureSkipVerify, nil)
	if err != nil {
		log.Fatal(err)
	}

	// start the upstream mock SMTP server, which will reply in the channel
	mockReply := make(chan []byte, 1)
	go mockSMTPServer(t, outHostPort, mockReply)

	// start the proxy
	go startProxy(t, s)

	// Exercise various combinations of security, logging, whether expecting a tracking link to show up in the output etc
	sendAndCheckEmails(t, inHostPort, 20, "", mockReply, PlainEmail) // plaintext email (won't be tracked)

	sendAndCheckEmails(t, inHostPort, 20, "", mockReply, RandomTestEmail) // html email

	sendAndCheckEmails(t, inHostPort, 20, "STARTTLS", mockReply, PlainEmail) // plaintext email (won't be tracked)

	sendAndCheckEmails(t, inHostPort, 20, "STARTTLS", mockReply, RandomTestEmail) // html email

	// Flip the logging to non-verbose after the first pass, to exercise that path
	be.SetVerbose(false)
	sendAndCheckEmails(t, inHostPort, 20, "STARTTLS", mockReply, RandomTestEmail)
}

func sendAndCheckEmails(t *testing.T, inHostPort string, n int, secure string, mockReply chan []byte, makeEmail func() string) {
	// Allow server a little while to start, then send a test mail using standard net/smtp.Client
	c, err := smtp.Dial(inHostPort)
	for i := 0; err != nil && i < 10; i++ {
		time.Sleep(time.Millisecond * 100)
		c, err = smtp.Dial(inHostPort)
	}
	if err != nil {
		t.Fatalf("Can't connect to proxy: %v\n", err)
	}
	// EHLO
	err = c.Hello("localhost")
	if err != nil {
		t.Error(err)
	}

	// STARTTLS
	if strings.ToUpper(secure) == "STARTTLS" {
		if tls, _ := c.Extension("STARTTLS"); tls {
			// client uses same certs as mock server and proxy, which seems fine for testing purposes
			cfg, err := tlsClientConfig(localhostCert, localhostKey)
			if err != nil {
				t.Error(err)
			}
			// only upgrade connection if not already in TLS
			if _, isTLS := c.TLSConnectionState(); !isTLS {
				err = c.StartTLS(cfg)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}

	// Check AUTH supported
	ok, param := c.Extension("AUTH")
	if !ok {
		t.Errorf("Got %v, expected %v, param=%s\n", ok, true, param)
	}

	// AUTH
	auth := smtp.PlainAuth("", "user@example.com", "password", "localhost")
	err = c.Auth(auth)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		// Submit an email .. MAIL FROM, RCPT TO, DATA ...
		err = c.Mail(RandomRecipient())
		if err != nil {
			t.Error(err)
		}
		err = c.Rcpt(RandomRecipient())
		if err != nil {
			t.Error(err)
		}
		w, err := c.Data()
		if err != nil {
			t.Error(err)
		}
		testEmail := makeEmail()
		r := strings.NewReader(testEmail)
		bytesWritten, err := io.Copy(w, r)
		if err != nil {
			t.Error(err)
		}
		if int(bytesWritten) != len(testEmail) {
			t.Fatalf("Unexpected DATA copy length %v", bytesWritten)
		}

		err = w.Close() // Close the data phase
		if err != nil {
			t.Error(err)
		}

		// Collect the response from the mock server
		mockr := <-mockReply

		// buf now contains the "wrapped" email
		outputMail, err := mail.ReadMessage(bytes.NewReader(mockr))
		if err != nil {
			t.Error(err)
		}
		inputMail, err := mail.ReadMessage(strings.NewReader(testEmail))
		if err != nil {
			t.Error(err)
		}
		compareInOutMail(t, inputMail, outputMail)
	}

	// Provoke unknown command
	id, err := c.Text.Cmd("WEIRD")
	if err != nil {
		t.Error(err)
	}
	c.Text.StartResponse(id)
	code, msg, err := c.Text.ReadResponse(501)
	t.Log("Response to WEIRD command:", code, msg)
	if code != 501 {
		t.Fatalf("Provoked unknown command - got error %v", err)
	}
	c.Text.EndResponse(id)

	// RESET is not part of the usual happy path for a message ,but we can test
	err = c.Reset()
	if err != nil {
		t.Error(err)
	}

	// QUIT
	err = c.Quit()
	if err != nil {
		t.Error(err)
	}
}

func compareInOutMail(t *testing.T, inputMail *mail.Message, outputMail *mail.Message) {
	// check the headers match
	for hdrType, _ := range inputMail.Header {
		in := inputMail.Header.Get(hdrType)
		out := outputMail.Header.Get(hdrType)
		if in != out {
			t.Errorf("Header %v mismatch", hdrType)
		}
	}

	// Compare body lengths
	inBody, err := ioutil.ReadAll(inputMail.Body)
	if err != nil {
		t.Error(err)
	}
	outBody, err := ioutil.ReadAll(outputMail.Body)
	if err != nil {
		t.Error(err)
	}

	// Compare lengths - should be nonzero and within an approx ratio of each other.
	inL := len(inBody)
	outL := len(outBody)
	if inL != outL {
		t.Errorf("Output email length %d, was expecting %d\n", outL, inL)
	}
}

func makeFakeSession(t *testing.T, be *smtpproxy.ProxyBackend, url string) smtpproxy.Session {
	c, err := textproto.Dial("tcp", url)
	if err != nil {
		t.Error(err)
	}
	return be.MakeSession(&smtpproxy.Client{Text: c})
}

func TestProxyFaultyInputs(t *testing.T) {
	outHostPort := ":9988"
	verboseOpt := false // vary this from the usual
	insecureSkipVerify := true

	// Set up parameters that the backend will use, and initialise the proxy server parameters
	be := smtpproxy.NewBackend(outHostPort, verboseOpt, insecureSkipVerify)
	_, err := be.Init() // expect an error
	if err == nil {
		t.Errorf("This test should have returned a non-nil error code")
	}

	const dummyServer = "example.com:80"
	// Provoke error path in Greet (hitting an http server, not an smtp one)
	s := makeFakeSession(t, be, dummyServer)
	caps, code, msg, err := s.Greet("EHLO")
	if err == nil {
		t.Errorf("This test should have returned a non-nil error code")
	}

	// Provoke error path in STARTTLS. Need to get a fresh connection each time
	s = makeFakeSession(t, be, dummyServer)
	code, msg, err = s.StartTLS()
	if err == nil {
		t.Errorf("This test should have returned a non-nil error code")
	}

	// Exercise the session unknown command handler (passthru)
	s = makeFakeSession(t, be, dummyServer)
	code, msg, err = s.Unknown(0, "NONSENSE", "")
	if err == nil {
		t.Errorf("This test should have returned a non-nil error code")
	}

	// Exercise the error paths in DataCommand
	s = makeFakeSession(t, be, dummyServer)
	w, code, msg, err := s.DataCommand()
	if err == nil {
		t.Errorf("This test should have returned a non-nil error code")
	}

	// Exercise the error paths in Data (body)
	s = makeFakeSession(t, be, dummyServer)
	r := strings.NewReader("it is only the hairs on a gooseberry") // this should cause a mailcopy error, as it's not valid RFC822
	code, msg, err = s.Data(r, myWriteCloser{Writer: ioutil.Discard})

	/*
		if err == nil {
			t.Errorf("This test should have returned a non-nil error code")
		}
	*/

	// Valid input mail, but cannot write to the destination stream
	s = makeFakeSession(t, be, dummyServer)
	testEmail := RandomTestEmail()
	r = strings.NewReader(testEmail)
	code, msg, err = s.Data(r, brokenWriteCloser(t))
	if err == nil {
		t.Errorf("This test should have returned a non-nil error code")
	}

	// Valid input mail and output stream, but broken upstream debug stream
	s = makeFakeSession(t, be, dummyServer)
	r = strings.NewReader(testEmail)
	// Set up parameters that the backend will use, and initialise the proxy server parameters
	be2 := smtpproxy.NewBackend(outHostPort, verboseOpt, insecureSkipVerify)
	s = makeFakeSession(t, be2, dummyServer)
	code, msg, err = s.Data(r, myWriteCloser{Writer: ioutil.Discard})
	/*
		if err == nil {
			t.Errorf("This test should have returned a non-nil error code")
		}
	*/

	_, _, _, _ = caps, code, msg, w // workaround these variables being "unused" yet useful for debugging the test
}

// Deliberately return a WriteCloser that should break
func brokenWriteCloser(t *testing.T) io.WriteCloser {
	f := alreadyClosedFile(t)
	return myWriteCloser{Writer: f}
}

// Deliberately return an unusable file handle
func alreadyClosedFile(t *testing.T) *os.File {
	f, err := ioutil.TempFile(".", "tmp")
	if err != nil {
		t.Error(err)
	}
	err = f.Close()
	if err != nil {
		t.Error(err)
	}
	os.Remove(f.Name())
	return f
}

//-----------------------------------------------------------------------------
// test email & html templates

// string params: initial_pixel, testTargetURL, end_pixel
const testHTMLTemplate1 = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>test mail</title>
</head>
<body>%s
  Click <a href="%s">SparkPost</a>
  <p>This is a very long line of text indeed containing !"#$%%&'()*+,-./0123456789:; escaped
    ?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[ ]^_abcdefghijklmnopqrstuvwxyz ~</p>
  <p>Here's some exotic characters to work the quoted-printable stuff ¡¢£¤¥¦§¨©ª« ¡¢£¤¥¦§¨©ª«
  </p>
  Click <a href="%s">Another tracked link</a>
%s</body>
</html>
`

const testTextTemplate1 = `Spicy jalapeno bacon ipsum dolor amet pariatur mollit fatback venison, cillum occaecat quis ut labore pork belly culpa ea bacon in spare ribs.`

// string params: to, from, bound, bound, testTextTemplate1, bound, testHTML, bound
const testEmailTemplate = `To: %s
From: %s
Subject: Fresh, tasty Avocados delivered straight to your door!
Content-Type: multipart/alternative; boundary="%s"
MIME-Version: 1.0

--%s
Content-Transfer-Encoding: 7bit
Content-Type: text/plain; charset="UTF-8"

%s

--%s
Content-Transfer-Encoding: 8bit
Content-Type: text/html; charset="UTF-8"

%s
--%s--
`

func testHTML(htmlTemplate, URL1, URL2 string) string {
	return fmt.Sprintf(htmlTemplate, "", URL1, URL2, "")
}

// RandomTestEmail creates HTML body contents, and places inside an email
func RandomTestEmail() string {
	URL1 := RandomURLWithPath()
	URL2 := RandomURLWithPath()
	testHTML := testHTML(testHTMLTemplate1, URL1, URL2)
	to := RandomRecipient()
	from := RandomRecipient()
	u := uuid.New() // randomise boundary marker
	bound := fmt.Sprintf("%0x", u[:8])
	return fmt.Sprintf(testEmailTemplate, to, from, bound, bound, testTextTemplate1, bound, testHTML, bound)
}

const plainEmailTemplate = `To: %s
From: %s
Subject: A plaintext email
MIME-Version: 1.0

short plaintext
`

func PlainEmail() string {
	to := RandomRecipient()
	from := RandomRecipient()
	return fmt.Sprintf(plainEmailTemplate, to, from)
}

func RandomWord() string {
	const dict = "abcdefghijklmnopqrstuvwxyz"
	l := rand.Intn(20) + 1
	s := ""
	for ; l > 0; l-- {
		p := rand.Intn(len(dict))
		s = s + string(dict[p])
	}
	return s
}

// A completely random URL (not belonging to any actual TLD), pathlen should be >= 0
func RandomURL(pathlen int) string {
	var method string
	if rand.Intn(2) > 0 {
		method = "https"
	} else {
		method = "http"
	}
	path := ""
	for ; pathlen > 0; pathlen-- {
		path = path + "/" + RandomWord()
	}
	return method + "://" + RandomWord() + "." + RandomWord() + path
}

func RandomBaseURL() string {
	return RandomURL(0)
}

func RandomURLWithPath() string {
	return RandomURL(rand.Intn(4))
}

func RandomRecipient() string {
	return RandomWord() + "@" + RandomWord() + "." + RandomWord()
}

//-----------------------------------------------------------------------------
/*
func TestClientOtherFunctions(t *testing.T) {
	// client uses same certs as mock server and proxy, which seems fine for testing purposes
	cfg, err := tlsClientConfig(localhostCert, localhostKey)
	if err != nil {
		t.Error(err)
	}
	// DialTLS is not used by the proxy app in its current form, but may be useful
	smtps := "smtp.gmail.com:465"
	c, err := smtpproxy.DialTLS(smtps, cfg)
	if err != nil {
		t.Error(err)
	}

	// Greet the endpoint
	code, msg, err := c.Hello("there")
	if err != nil {
		t.Errorf("code %v msg %v err %v\n", code, msg, err)
	}

	// Check extensions
	ok, params := c.Extension("AUTH")
	if !ok {
		t.Errorf("ok %v, expected %v, params %v\n", ok, true, params)
	}

	// Close
	err = c.Close()
	if err != nil {
		t.Error(err)
	}
}

/*
func TestServerOtherFunctions(t *testing.T) {
	verboseOpt := true
	insecureSkipVerify := true
	// Logging of downstream (client to proxy server) commands and responses
	dbgFile, err := smtpproxy.DownstreamDebug(downstreamDebug)
	if err != nil {
		log.Fatal(err)
	}

	s, _, err := smtpproxy.CreateProxy("localhost:5586", outHostPort, verboseOpt, localhostCert, localhostKey, insecureSkipVerify, dbgFile)
	if err != nil {
		log.Fatal(err)
	}

	// start the proxy
	go startProxy(t, s)
	time.Sleep(1 * time.Second)
	// Test additional server functions not used by the app
	f := func(c *smtpproxy.Conn) {
		fmt.Printf("%v\n", c)
	}
	s.ForEachConn(f)
}
*/
