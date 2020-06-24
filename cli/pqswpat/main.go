package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
)

const (
	WorkModeServer = iota
	WorkModeClient = iota
)

var configFile string
var workMode int
var doHelp bool
var listenAddr string

func doParsing() bool {
	flag.StringVar(&configFile, "c", "pqswpat.conf", "PQSW config file")
	flag.BoolVar(&doHelp, "h", false, "Show usage")
	flag.Parse()
	if doHelp {
		fmt.Printf("Usage of %v: <server|client> <host:port>\n", os.Args[0])
		fmt.Println("A simple broadcast server/client. Server receives connections and forwards messages to all connected clients.")
		flag.PrintDefaults()
		fmt.Println()
		return false
	}
	if flag.NArg() != 2 {
		fmt.Println("You need to provide two parameters: working mode and binding.")
		return false
	}
	if flag.NArg() == 0 {
		fmt.Println("Need to specify some arguments. Try using -h.")
		return false
	}
	switch os.Args[len(os.Args)-2] {
	case "server":
		workMode = WorkModeServer
	case "client":
		workMode = WorkModeClient
	default:
		fmt.Println("You must provide a working mode, either listen or connect.")
		return false
	}

	mapping := os.Args[len(os.Args)-1]
	re, _ := regexp.Compile(`^(.*):(\d*)$`)
	maps := re.FindStringSubmatch(mapping)
	if len(maps) == 0 {
		fmt.Println("Please provide a forwarding in the format: host:port")
		return false
	}
	listenAddr = maps[1] + ":" + maps[2]
	return true
}

func main() {
	if doParsing() {
		fmt.Println("do work")

	}
}
