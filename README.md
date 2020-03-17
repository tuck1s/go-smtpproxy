# go-smtpproxy
Go package, based heavily on [emersion's go-gmtp](https://github.com/emersion/go-smtp), with increased transparency of response codes and no sasl dependency.
The purpose of this is to provide functions that act as a server to receive SMTP messages from your downstream client. These SMTP messages are relayed through to
an upstream server.

The command / response exchanges are passed on transparently.

STARTTLS can be offered to the downstream client if you configure a valid certificate/key pair.

STARTTLS can be requested from the upstream server.

[Line splitting](linesplitter.go) functions are included for base64 encoded email handling by your app.

Get this project with `go get github.com/tuck1s/go-smtpproxy`.

`cmd/proxy` contains an example command-line app using this library:

```bash
cd cmd/proxy
go build
./proxy -h

SMTP proxy that accepts incoming messages from your downstream client, and relays on to an upstream server.
Usage of ./proxy:
  -certfile string
        Certificate file for this server
  -downstream_debug string
        File to write downstream server SMTP conversation for debugging
  -in_hostport string
        Port number to serve incoming SMTP requests (default "localhost:587")
  -insecure_skip_verify
        Skip check of peer cert on upstream side
  -logfile string
        File written with message logs (also to stdout)
  -out_hostport string
        host:port for onward routing of SMTP requests (default "smtp.sparkpostmail.com:587")
  -privkeyfile string
        Private key file for this server
  -verbose
        print out lots of messages
```