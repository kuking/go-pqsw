package main

import (
	"flag"
	"fmt"
	"github.com/kuking/go-pqsw/config"
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

By default it will listen to as many connections as possible. Further documentation here: https://github.com/kuking/go-pqsw`)
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

func handleNewConnection(conn net.Conn, cfg *config.Config) {
	var err error
	var sw *wire.SecureWire
	if workMode == WorkModeExit {
		sw, err = wire.ServerHandshake(conn, cfg)
		if err != nil {
			fmt.Println(fmt.Errorf("server could not establish sercure wire, err=%v", err))
			return
		}
	}
	connTo, err := net.Dial("tcp", connectAddr)
	if err != nil {
		fmt.Println("Could not connect to:", connectAddr, "with error", err)
		if sw != nil {
			_ = sw.Close()
		}
		_ = conn.Close()
		return
	}
	if workMode == WorkModeEntry {
		sw, err = wire.ClientHandshake(connTo, cfg)
		if err != nil {
			fmt.Println(fmt.Errorf("could not secure connection to '%v' with err=%v", connectAddr, err))
			_ = conn.Close()
			return
		}
	}

	if workMode == WorkModeExit {
		go copyTo(sw, connTo)
		go copyTo(connTo, sw)
	} else {
		go copyTo(conn, sw)
		go copyTo(sw, conn)
	}
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

func doListen(cfg *config.Config) {
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
			go handleNewConnection(conn, cfg)
		}
	}
}

func main() {
	if doParsing() {
		cfg, err := config.LoadFrom(configFile)
		if err != nil {
			fmt.Println(fmt.Errorf("could not read the config file, err=%v", err))
			os.Exit(-1)
		}
		doListen(cfg)
	}
}
