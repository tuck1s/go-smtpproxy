package smtpproxy

import (
	"log"

	"gopkg.in/natefinch/lumberjack.v2" // timed rotating log handler
)

// MyLogger sets up a custom logger, if filename is given, emitting to stdout as well
// If filename is blank string, then output is stdout only
func MyLogger(filename string) {
	if filename != "" {
		log.SetOutput(&lumberjack.Logger{
			Filename: filename,
			MaxAge:   7,    //days
			Compress: true, // disabled by default
		})
	}
}

//-----------------------------------------------------------------------------

// PositionIn returns the position of a value within an array of strings, if an element exactly matches val
func PositionIn(arr []string, val string) (int, bool) {
	for i, v := range arr {
		if v == val {
			return i, true
		}
	}
	return 0, false
}
