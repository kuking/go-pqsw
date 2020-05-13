package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/kuking/go-pqsw/wire"
	"io"
	"net"
	"os"
	"regexp"
)

var listenAddr string
var connectAddr string
var configFile string
var workMode int
var doHelp bool

//FIXME:
// fix it to $ pqswtun -c config.conf wrap 4444:localhost:8888
// (instead of -l 4444)
// enc / dec

const (
	WorkModeEntry = iota
	WorkModeExit  = iota

	NetworkBufferSize = 64 * 1024
)

func doParsing() bool {
	flag.StringVar(&configFile, "c", "pqswtun.conf", "PQSW config file")
	flag.BoolVar(&doHelp, "h", false, "Show usage")
	flag.Parse()
	if doHelp {
		fmt.Printf("Usage of %v: <entry|exit> <[bind_address:]port:host:hostport>\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Println(`
NOTES:

entry: accepts plain text traffic, forwarding it securely to the host:hostport i.e. (localhost)$ pqswtun entry localhost:1022:remote:2222
 exit: takes the encrypted traffic, decrypts it and forwards it to the host:hostport i.e (remote)$ pqswtun exit 2222:localhost:22

A configuration file is required (default: pqswtun.conf) with at least three entries:
 - a full private/public key for the client
 - a public key for the host
 - a pre-shared pragmatic one-time-pad (potp)

For creating a configuration file, use the utility pqswcfg, i.e. $ pqswcfg create vanilla pqswtun.cfg
the configuration file can be easily copied-and-pasted and manipulated as it is a json file.

By default it will listen to as many connections as possible. Further documentation here: https://github.com/kuking/go-pqsw ")

WORK IN PROGRESS - THIS USES A FIXED KEY - COME BACK SOON`)
		return false
	}
	if flag.NArg() > 2 {
		fmt.Print("Too many arguments.")
		return false
	}
	if flag.NArg() == 0 {
		fmt.Println("Need to specify some arguments. Try using -h.")
		return false
	}
	switch os.Args[len(os.Args)-2] {
	case "entry":
		workMode = WorkModeEntry
	case "exit":
		workMode = WorkModeExit
	default:
		fmt.Println("You must provide a working mode, either listen or connect.")
		return false
	}

	mapping := os.Args[len(os.Args)-1]
	re, _ := regexp.Compile(`^((.*):)?(\d*){1}:(.*){1}:(\d*){1}$`)
	maps := re.FindStringSubmatch(mapping)
	if len(maps) == 0 {
		fmt.Println("Please provide a forwarding in the format: [bind_address:]port:host:hostport ")
		return false
	}
	listenAddr = maps[2] + ":" + maps[3]
	connectAddr = maps[4] + ":" + maps[5]
	return true
}

func handleListenConnection(conn net.Conn) {
	connTo, err := net.Dial("tcp", connectAddr)
	if err != nil {
		fmt.Println("Could not connect to:", connectAddr, "with error", err)
		return
	}
	if workMode == WorkModeEntry {
		connTo, err = wrapSecure(connTo)
		if err != nil {
			fmt.Println("Could not secure connection to:", connectAddr, "with error", err)
		}
	}
	go copyTo(conn, connTo)
	go copyTo(connTo, conn)
}

func copyTo(from net.Conn, to net.Conn) {
	defer from.Close()
	defer to.Close()
	buf := make([]byte, NetworkBufferSize)
	for {
		//from.SetReadDeadline(time.Now())
		n, err := from.Read(buf)
		if err == io.EOF {
			fmt.Println("Closed connection with", from.RemoteAddr())
			return
		}
		if err != nil {
			fmt.Println("Failed to read from", from.RemoteAddr(), "with error", err)
			return
		}
		m, err := to.Write(buf[:n])
		if err != nil {
			fmt.Println("Failed to write to", from.RemoteAddr(), "with error", err)
			return
		}
		if n != m {
			fmt.Println("Failed to write everything; read=", n, "written=", m)
			return
		}
	}
}

func wrapSecure(conn net.Conn) (net.Conn, error) {
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	nonce, _ := hex.DecodeString("001122334455667788990011")
	return wire.NewSecureWireAES256CGM(key, nonce, conn)
}

func doListen() {
	ln, err := net.Listen("tcp", listenAddr)
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
			if workMode == WorkModeExit {
				conn, err = wrapSecure(conn)
			}
			if err != nil {
				fmt.Println("Error securing channel", err)
			} else {
				go handleListenConnection(conn)
			}
		}
	}
}

func main() {
	if doParsing() {
		doListen()
	}
}
