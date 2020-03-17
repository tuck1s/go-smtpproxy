// proxy command-line example
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/tuck1s/go-smtpproxy"
)

func main() {
	inHostPort := flag.String("in_hostport", "localhost:587", "Port number to serve incoming SMTP requests")
	outHostPort := flag.String("out_hostport", "smtp.sparkpostmail.com:587", "host:port for onward routing of SMTP requests")
	certfile := flag.String("certfile", "", "Certificate file for this server")
	privkeyfile := flag.String("privkeyfile", "", "Private key file for this server")
	logfile := flag.String("logfile", "", "File written with message logs (also to stdout)")
	verboseOpt := flag.Bool("verbose", false, "print out lots of messages")
	downstreamDebug := flag.String("downstream_debug", "", "File to write downstream server SMTP conversation for debugging")
	insecureSkipVerify := flag.Bool("insecure_skip_verify", false, "Skip check of peer cert on upstream side")
	flag.Usage = func() {
		const helpText = "SMTP proxy that accepts incoming messages from your downstream client, and relays on to an upstream server.\n" +
			"Usage of %s:\n"
		fmt.Fprintf(flag.CommandLine.Output(), helpText, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	smtpproxy.MyLogger(*logfile)
	fmt.Println("Starting smtp proxy service on port", *inHostPort, ", logging to", *logfile)
	log.Println("Starting smtp proxy service on port", *inHostPort)
	log.Println("Outgoing host:port set to", *outHostPort)

	// Set up parameters that the backend will use
	be := NewBackend(*outHostPort, *verboseOpt, *insecureSkipVerify)
	s := smtpproxy.NewServer(be)
	s.Addr = *inHostPort
	s.ReadTimeout = 60 * time.Second
	s.WriteTimeout = 60 * time.Second
	var err error

	// Gather TLS credentials for the proxy server
	if *certfile != "" && *privkeyfile != "" {
		cert, err := ioutil.ReadFile(*certfile)
		if err != nil {
			log.Fatal(err)
		}
		privkey, err := ioutil.ReadFile(*privkeyfile)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Gathered certificate", *certfile, "and key", *privkeyfile)
		err = s.ServeTLS(cert, privkey)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Println("certfile or privkeyfile not specified - proxy will NOT offer STARTTLS to clients")
		s.Domain, err = os.Hostname() // This is the fallback in case we have no cert / privkey to give us a Subject
		if err != nil {
			log.Fatal("Can't read hostname")
		}
	}

	log.Println("Proxy will advertise itself as", s.Domain)
	log.Println("Verbose SMTP conversation logging:", *verboseOpt)
	log.Println("insecure_skip_verify (Skip check of peer cert on upstream side):", *insecureSkipVerify)

	// Logging of downstream (client to proxy server) commands and responses
	if *downstreamDebug != "" {
		dbgFile, err := os.OpenFile(*downstreamDebug, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer dbgFile.Close()
		s.Debug = dbgFile
		log.Println("Proxy logging SMTP commands, responses and downstream DATA to", dbgFile.Name())
	}

	// Begin serving requests
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
