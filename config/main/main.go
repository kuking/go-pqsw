package main

import (
	"fmt"
	"github.com/kuking/go-pqsw/config"
	"log"
	"os"
)

func saveConfigAndFinish(config *config.Config, file string) {
	err := config.SaveTo(file)
	if err != nil {
		log.Panic(err)
	} else {
		os.Exit(0)
	}
}
func main() {
	// There is probably a library to manage this better, but I will never finish this. Let me know if you know one :-)
	if len(os.Args) > 2 && os.Args[1] == "help" {
		if os.Args[2] == "help" {
			showConfigHelp()
		}

	}
	if len(os.Args) > 1 && os.Args[1] == "config" {
		if len(os.Args) == 4 && os.Args[2] == "create" {
			saveConfigAndFinish(config.NewEmpty(), os.Args[3])
		}
		if len(os.Args) == 4 && os.Args[2] == "vanilla" {
			cfg := config.NewEmpty()
			err := cfg.CreateAndAddKey(config.KeyTypeSidhFp751)
			if err != nil {
				panic(err)
			}
			saveConfigAndFinish(cfg, os.Args[3])
		}

		if len(os.Args) == 4 && os.Args[2] == "show" {
			cfg, err := config.LoadFrom(os.Args[3])
			if err != nil {
				log.Panic(err)
			}
			fmt.Printf("Config file '%s' loaded, it contains:\n", os.Args[3])
			fmt.Println(len(cfg.Keys), "Keys")
			fmt.Println(len(cfg.Otps), "OTP Datasets")
			fmt.Println(len(cfg.Uniques), "Unique replay store")
			os.Exit(0)
		}

		showConfigHelp()
	}

	if len(os.Args) > 1 && os.Args[1] == "key" {
		if len(os.Args) < 3 {
			showKeyHelp()
		}
		if os.Args[2] == "create" {

		}
	}
	showGeneralHelp()
}

func showGeneralHelp() {
	fmt.Println(`Post Quantum Secure Wire Configuration Management

Usage:

         pqswcfg <command> [arguments]

The commands are:

         config	   manages configuration files
         key       manages keys in the key store, including creation.
         otp       manages one time password files
         uniq      manages unique ids memories

Use "ks help <command>" for more information about a command.`)
	os.Exit(0)
}

func showConfigHelp() {
	fmt.Println(`Usage: config <sub command> <configuration file>

The Sub commands are:
         create    creates an empty new configuration file
         vanilla   creates a new configuration file with typical defaults
         show      loads a configuration file and shows details
         verify    verifies its contents are coherent and valid`)
	os.Exit(0)
}

func showKeyHelp() {
	fmt.Println(`

Usage: 

         ks key <command> [arguments]

The commands are:

         create    creates a new key and adds it to the store
         delete    deletes a key
         list      list all the keys
         import    imports a key
         export    exports a key

Use 
ks key del <key-id> `)
	os.Exit(0)
}
