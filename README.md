# go-smtpproxy
Go package, based heavily on [emersion's go-gmtp](https://github.com/emersion/go-smtp), with increased transparency of response codes and no sasl dependency.
The purpose of this is to provide functions that act as a server to receive SMTP messages from your downstream client. These SMTP messages are relayed through to
an upstream server.

The command / response exchanges are passed on transparently.

STARTTLS can be offered to the downstream client if you configure a valid certificate/key pair.

STARTTLS can be requested to the upstream server.

## Pre-requisites
- Git & Golang - installation tips [here](#installing-git-golang-on-your-host)

Get this project with `go get github.com/tuck1s/go-smtpproxy`

## Installation, configuration

TODO