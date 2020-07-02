package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/kuking/go-pqsw/config"
	"github.com/kuking/go-pqsw/wire"
	"io"
	"net"
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
var hostPort string

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
	hostPort = maps[1] + ":" + maps[2]
	return true
}

func handleServerConnection(conn net.Conn, cfg *config.Config) {
	var err error
	sw, err := wire.ServerHandshake(conn, cfg)
	if err != nil {
		fmt.Println(fmt.Errorf("server could not establish sercure wire, err=%v", err))
		return
	}
	go lineCopier("server' stdin->wire", os.Stdin, sw)
	go lineCopier("server' wire->stdout", sw, os.Stdout)
}

func doListen(cfg *config.Config) {
	ln, err := net.Listen("tcp", hostPort)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Listening %v ...\n", ln.Addr())
	for {
		conn, err := ln.Accept()
		fmt.Printf("New connection from %v ...\n", conn.RemoteAddr())
		if err != nil {
			fmt.Println("Error accepting connection", err)
		} else {
			go handleServerConnection(conn, cfg)
		}
	}
}

func doConnect(cfg *config.Config) {
	fmt.Printf("Connecting to %v ...\n", hostPort)
	ln, err := net.Dial("tcp", hostPort)
	if err != nil {
		panic(err)
	}
	sw, err := wire.ClientHandshake(ln, cfg)
	if err != nil {
		panic(err)
	}
	go lineCopier("client' stdin->wire", os.Stdin, sw)
	lineCopier("client' wire->stdout", sw, os.Stdout)
}

func lineCopier(desc string, r io.ReadCloser, w io.WriteCloser) {
	defer r.Close()
	defer w.Close()
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		w.Write(append(scanner.Bytes(), '\n'))
	}
	fmt.Println("Closing", desc)
}

func main() {
	if doParsing() {
		cfg, err := config.LoadFromInteractive(configFile)
		if err != nil {
			fmt.Println(fmt.Errorf("could not read the config file, err=%v", err))
			os.Exit(-1)
		}
		if workMode == WorkModeServer {
			doListen(cfg)
		} else {
			doConnect(cfg)
		}
	}
}
