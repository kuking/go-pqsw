package main

import (
	"flag"
	"fmt"
	"os"
)

var configFile string
var doHelp bool

func doParsing() bool {
	flag.StringVar(&configFile, "c", "pqswpat.conf", "PQSW config file")
	flag.BoolVar(&doHelp, "h", false, "Show usage")
	flag.Parse()
	if doHelp {
		fmt.Printf("Usage of %v: <listen|connect> <host:port>\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Println()
		return false
	}
	return true

}

func main() {
	if doParsing() {
		fmt.Println("do work")

	}
}
