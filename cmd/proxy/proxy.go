// proxy command-line example
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/tuck1s/go-smtpproxy"
	"gopkg.in/natefinch/lumberjack.v2" // timed rotating log handler
)

// myLogger sets up a custom logger, if filename is given, emitting to stdout as well
// If filename is blank string, then output is stdout only
func myLogger(filename string) {
	if filename != "" {
		log.SetOutput(&lumberjack.Logger{
			Filename: filename,
			MaxAge:   7,    //days
			Compress: true, // disabled by default
		})
	}
}

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
	myLogger(*logfile)
	fmt.Println("Starting smtp proxy service on port", *inHostPort, ", logging to", *logfile)
	log.Println("Starting smtp proxy service on port", *inHostPort)
	log.Println("Outgoing host:port set to", *outHostPort)

	var cert, privkey []byte
	var err error
	// Gather TLS credentials for the proxy server
	if *certfile != "" && *privkeyfile != "" {
		cert, err = ioutil.ReadFile(*certfile)
		if err != nil {
			log.Fatal(err)
		}
		privkey, err = ioutil.ReadFile(*privkeyfile)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Gathered certificate", *certfile, "and key", *privkeyfile)
	} else {
		log.Println("certfile or privkeyfile not specified - proxy will NOT offer STARTTLS to clients")
	}

	// Logging of downstream (client to proxy server) commands and responses
	var dbgFile *os.File
	if *downstreamDebug != "" {
		dbgFile, err = os.OpenFile(*downstreamDebug, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		} else {
			defer dbgFile.Close()
			log.Println("Proxy logging SMTP commands, responses and downstream DATA to", dbgFile.Name())
		}
	}

	s, _, err := smtpproxy.CreateProxy(*inHostPort, *outHostPort, *verboseOpt, cert, privkey, *insecureSkipVerify, dbgFile)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Proxy will advertise itself as", s.Domain)
	log.Println("Verbose SMTP conversation logging:", *verboseOpt)
	log.Println("insecure_skip_verify (Skip check of peer cert on upstream side):", *insecureSkipVerify)

	// Begin serving requests
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
