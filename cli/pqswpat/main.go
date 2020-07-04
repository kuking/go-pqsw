package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/kuking/go-pqsw/config"
	"github.com/kuking/go-pqsw/cryptoutil"
	"github.com/kuking/go-pqsw/wire"
	"io"
	"math/rand"
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

// ---------- server code ---------------------------------------------------------------------------------------------

type ClientConnection struct {
	Id             uint64
	Wire           *wire.SecureWire
	ServerToClient chan string
}

var ClientConnectionsLock sync.RWMutex
var ClientConnections = make([]ClientConnection, 0)
var ClientToServer = make(chan string, 100)
var ClientToServerDisconnect = make(chan uint64, 100)

func handleServerConnection(conn net.Conn, cfg *config.Config) {
	var err error
	sw, err := wire.ServerHandshake(conn, cfg)
	if err != nil {
		fmt.Println(fmt.Errorf("server could not establish sercure wire, err=%v", err))
		return
	}
	conn.RemoteAddr().String()
	clientConnection := ClientConnection{
		Id:             rand.Uint64(),
		Wire:           sw,
		ServerToClient: make(chan string, 10),
	}
	ClientConnectionsLock.Lock()
	ClientConnections = append(ClientConnections, clientConnection)
	ClientConnectionsLock.Unlock()

	go handleClientWithinServer(clientConnection)
}

func handleClientWithinServer(conn ClientConnection) {
	remoteKeyId := conn.Wire.RemoteKeyId()
	localKeyId := conn.Wire.LocalKeyId()
	fmt.Printf("%x: %v connected using client key %v and server key %v\n",
		conn.Id, conn.Wire.RemoteAddr(), cryptoutil.EncB64(remoteKeyId[:]), cryptoutil.EncB64(localKeyId[:]))
	wireChan := make(chan *string)
	scanner := bufio.NewScanner(conn.Wire)
	go scannerToChan(scanner, wireChan)
	for {
		select {
		case msg := <-conn.ServerToClient:
			_, err := conn.Wire.Write(append([]byte(msg), '\n'))
			if err != nil {
				fmt.Printf("%x: can not write to client\n", conn.Id)
				ClientToServerDisconnect <- conn.Id
				return
			}
		case msg := <-wireChan:
			if msg == nil {
				fmt.Printf("%x: remote disconnect\n", conn.Id)
				ClientToServerDisconnect <- conn.Id
				return
			} else {
				fmt.Printf("%x:> %v\n", conn.Id, *msg)
				ClientToServer <- *msg
			}
		}
	}
}

func scannerToChan(scanner *bufio.Scanner, wireChan chan *string) {
	for scanner.Scan() {
		var line = scanner.Text()
		wireChan <- &line
	}
	wireChan <- nil
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

		case id := <-ClientToServerDisconnect:
			ClientConnectionsLock.Lock()
			for i := 0; i < len(ClientConnections); i++ {
				if id == ClientConnections[i].Id {
					err := ClientConnections[i].Wire.Close()
					if err != nil {
						fmt.Printf("%x: could not close secure wire, error=%v\n", id, err)
					}
					ClientConnections = append(ClientConnections[:i], ClientConnections[i+1:]...)
					break
				}
			}
			fmt.Printf("%x: disposed\n", id)
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
		if err != nil {
			fmt.Println("Error accepting connection", err)
		} else {
			go handleServerConnection(conn, cfg)
		}
	}
}

// ---------- client code ---------------------------------------------------------------------------------------------

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
	go lineCopier(os.Stdin, sw)
	lineCopier(sw, os.Stdout)
}

func lineCopier(r io.ReadCloser, w io.WriteCloser) {
	defer r.Close()
	defer w.Close()
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		w.Write(append(scanner.Bytes(), '\n'))
	}
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
