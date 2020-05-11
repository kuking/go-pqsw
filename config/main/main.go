package main

import (
	"fmt"
	"github.com/kuking/go-pqsw/config"
	"github.com/kuking/go-pqsw/cryptoutil"
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
	doCmdHelp()
	doCmdConfig()
	doCmdKey()
	// otherwise
	showGeneralHelp()
}

func doCmdHelp() {
	// There is probably a library to manage this better, but I will never finish this. Let me know if you know one :-)
	args := os.Args
	if len(args) > 1 && args[1] == "help" {
		if len(args) == 2 {
			showGeneralHelp()
		}
		if len(args) == 3 && args[2] == "config" {
			showConfigHelp()
		}
		if len(args) == 3 && args[2] == "key" {
			showKeyHelp()
		}
		if len(args) == 4 && args[2] == "key" && args[3] == "create" {
			showKeyCreateHelp()
		}
		if len(args) == 4 && args[2] == "key" && args[3] == "delete" {
			showKeyDeleteHelp()
		}
	}
}

func doCmdConfig() {
	args := os.Args
	if len(args) > 1 && args[1] == "config" {
		if len(args) == 4 && args[2] == "create" {
			saveConfigAndFinish(config.NewEmpty(), args[3])
		}
		if len(args) == 4 && args[2] == "vanilla" {
			filename := args[3]
			cfg := config.NewEmpty()
			key, err := cfg.CreateAndAddKey(cryptoutil.KeyTypeSidhFp751)
			panicOnErr(err)
			if key == nil {
				fmt.Println("Key could not be created.")
				os.Exit(1)
			}
			cfg.ServerKey = key.Uuid
			cfg.ClientKey = key.Uuid
			potp, err := cfg.CreateInPlacePotp(1 * 4096)
			panicOnErr(err)
			if potp == nil {
				fmt.Println("Could not create PSK.")
			}
			cfg.ServerPotp = potp.Uuid
			cfg.ClientPotp = potp.Uuid
			fmt.Printf("Vanilla config created with Fp751 key '%v' and a PSK of 4096 bits '%v'\n",
				key.Uuid, potp.Uuid)
			panicOnErr(err)
			saveConfigAndFinish(cfg, filename)
		}
		if len(args) == 4 && args[2] == "show" {
			filename := args[3]
			cfg, err := config.LoadFrom(filename)
			panicOnErr(err)
			fmt.Printf("Config file '%s' loaded, it contains:\n", args[3])
			fmt.Println(len(cfg.Keys), "Keys")
			fmt.Println(len(cfg.Potps), "PSKs")
			fmt.Println(len(cfg.Uniques), "Unique replay store")
			os.Exit(0)
		}
		showConfigHelp()
	}
}

func doCmdKey() {
	args := os.Args
	if len(args) > 1 && args[1] == "key" {
		if len(args) == 5 && args[2] == "create" {
			keyTypeSt := args[3]
			keyType := cryptoutil.KeyTypeInvalid
			for k, v := range cryptoutil.KeyTypeAsString {
				if keyTypeSt == v {
					keyType = k
				}
			}
			if keyType == cryptoutil.KeyTypeInvalid {
				panic(fmt.Sprintf("I don't know how to generate a key of type: %s", keyTypeSt))
			}
			filename := args[4]

			cfg, err := config.LoadFrom(filename)
			panicOnErr(err)
			key, err := cfg.CreateAndAddKey(keyType)
			panicOnErr(err)
			cfg.ServerKey = key.Uuid
			panicOnErr(cfg.SaveTo(filename))
			fmt.Println("Key generated with keyId", key.Uuid)
			os.Exit(0)
		}
		if len(args) == 5 && args[2] == "delete" {
			uuid := args[3]
			filename := args[4]
			cfg, err := config.LoadFrom(filename)
			panicOnErr(err)
			if cfg.DeleteKeyByUUID(uuid) {
				panicOnErr(cfg.SaveTo(filename))
				fmt.Println("Key deleted with UUID", uuid)
				os.Exit(0)
			} else {
				fmt.Println("Could not find key.")
				os.Exit(-1)
			}
		}
		if len(args) == 4 && args[2] == "list" {
			cfg, err := config.LoadFrom(args[3])
			panicOnErr(err)
			for _, key := range cfg.Keys {
				ktype := "PUBONLY"
				if key.Pvt != "" {
					ktype = "PVT/PUB"
				}
				fmt.Printf("%s %s:%s\n", ktype, key.Type, key.Uuid)
			}
			os.Exit(0)
		}
		showKeyHelp()
	}
}

func panicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}

func showGeneralHelp() {
	fmt.Println(`Post Quantum Secure Wire Configuration Management

Usage:

         pqswcfg <command> [arguments]

The commands are:

         config	   manages configuration files
         key       manages keys in the key store, including creation.
         psk       manages pre shared keys 
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

func showKeyCreateHelp() {
	fmt.Println("Usage: ks key create <type> <config file>")
	fmt.Print("\nSupported key types: ")
	for _, v := range cryptoutil.KeyTypeAsString {
		fmt.Print(v, " ")
	}
	fmt.Println()
	os.Exit(0)
}

func showKeyDeleteHelp() {
	fmt.Println("Usage: ks key delete <key id> <config file>")
}
