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
	"sync"
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
		fmt.Printf(`Usage of %v: <server|client> <host:port>

A simple broadcast server and client. Server accepts connections and forwards messages to all connected clients.
Protocol is text based, messages are delimited by an end-of-line characters. Connection is over a PQSW secure wire.
When working as server it will output the traffic to its stdout but content sent to stdin will be ignored.
As client, broadcasted messages coming from the server will be output to stdout and anything sent to stdin will be
further forwarded to the server and be broadcasted to all clients (including itself, echoing it.)

`, os.Args[0])
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

type ClientConnection struct {
	Name           string
	Wire           *wire.SecureWire
	ServerToClient chan string
}

var ClientConnectionsLock sync.RWMutex
var ClientConnections = make([]ClientConnection, 0)
var ClientToServer = make(chan string, 100)

func handleServerConnection(conn net.Conn, cfg *config.Config) {
	var err error
	sw, err := wire.ServerHandshake(conn, cfg)
	if err != nil {
		fmt.Println(fmt.Errorf("server could not establish sercure wire, err=%v", err))
		return
	}
	conn.RemoteAddr().String()
	clientConnection := ClientConnection{
		Name:           conn.RemoteAddr().String(),
		Wire:           sw,
		ServerToClient: make(chan string, 10),
	}
	ClientConnectionsLock.Lock()
	ClientConnections = append(ClientConnections, clientConnection)
	ClientConnectionsLock.Unlock()

	go handleClientInServer(clientConnection)
}

func handleClientInServer(conn ClientConnection) {
	wireChan := make(chan string)
	scanner := bufio.NewScanner(conn.Wire)
	go scannerToChan(scanner, wireChan)
	for {
		select {
		case msg := <-conn.ServerToClient:
			conn.Wire.Write(append([]byte(msg), '\n'))
		case msg := <-wireChan:
			fmt.Println(conn.Name, "->", msg)
			ClientToServer <- msg
		}
		fmt.Println("handleClientInServer loop")
	}
}

func scannerToChan(scanner *bufio.Scanner, wireChan chan string) {
	for scanner.Scan() {
		wireChan <- scanner.Text()
	}
	close(wireChan)
}

func serverBroadcaster() {
	for {
		select {
		case msg := <-ClientToServer:
			ClientConnectionsLock.Lock()
			for _, clientConn := range ClientConnections {
				clientConn.ServerToClient <- msg
			}
			ClientConnectionsLock.Unlock()
		}
	}
}

func doServer(cfg *config.Config) {
	ln, err := net.Listen("tcp", hostPort)
	if err != nil {
		panic(err)
	}
	go serverBroadcaster()
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

func doClient(cfg *config.Config) {
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
			doServer(cfg)
		} else {
			doClient(cfg)
		}
	}
}
