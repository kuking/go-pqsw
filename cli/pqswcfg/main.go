package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kuking/go-pqsw/config"
	"github.com/kuking/go-pqsw/cryptoutil"
	"github.com/kuking/go-pqsw/misc"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
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
	doCmdPotp()
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
		if len(args) == 3 && args[2] == "potp" {
			showPotpHelp()
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
			potpSize := 2048
			keyType := cryptoutil.KeyTypeKyber1024
			cfg := config.NewEmpty()
			key, err := cfg.CreateAndAddKey(keyType, strconv.FormatInt(cfg.NextSequentialKeyCN(), 10))
			panicOnErr(err)
			if key == nil {
				fmt.Println("Key could not be created.")
				os.Exit(1)
			}
			cfg.PreferredKeyCN = key.CN
			potp, err := cfg.CreateAndAddInPlacePotp(potpSize, strconv.FormatInt(cfg.NextSequentialPotpCN(), 10))
			panicOnErr(err)
			if potp == nil {
				fmt.Println("Could not create PSK.")
			}
			cfg.PreferredPotpCN = potp.CN
			fmt.Printf("Vanilla config created with Kyber1024 key '%v' and a PSK of %v bits '%v'\n",
				key.Uuid, potpSize*8, potp.Uuid)
			panicOnErr(err)
			saveConfigAndFinish(cfg, filename)
		}
		if len(args) == 4 && args[2] == "encrypt" {
			filename := args[3]
			cfg, err := config.LoadFromInteractive(filename)
			if err != nil {
				fmt.Println("Could not read the config file", err)
				os.Exit(1)
			}
			if cfg.HasDiskEncryptionPassword() {
				fmt.Println("Changing current encryption password, please enter the new one (enter twice):")
			} else {
				fmt.Println("Encrypting the configuration file with a password (enter twice):")
			}
			pass1, err := misc.GetPassword()
			if err != nil {
				panic(err)
			}
			pass2, err := misc.GetPassword()
			if err != nil {
				panic(err)
			}
			if pass1 != pass2 {
				fmt.Println("I am sorry the passwords do not match.")
				os.Exit(1)
			}
			cfg.SetDiskEncryptionPassword(pass1)
			saveConfigAndFinish(cfg, filename)
		}
		if len(args) == 4 && args[2] == "decrypt" {
			filename := args[3]
			cfg, err := config.LoadFromInteractive(filename)
			if err != nil {
				fmt.Println("Could not read the config file", err)
				os.Exit(1)
			}
			if !cfg.HasDiskEncryptionPassword() {
				fmt.Println("The configuration file does not seems to be encrypted.")
				os.Exit(1)
			} else {
				fmt.Println("WARNING: The configuration file encryption has been removed. Keys are now in plain-text.")
			}
			cfg.SetDiskEncryptionPassword("")
			saveConfigAndFinish(cfg, filename)
		}
		if len(args) == 4 && args[2] == "show" {
			filename := args[3]
			cfg, err := config.LoadFromInteractive(filename)
			panicOnErr(err)
			fmt.Printf("Config file '%s' loaded, it contains:\n", args[3])
			fmt.Println(len(cfg.Keys), "Keys")
			fmt.Println(len(cfg.Potps), "PSKs")
			os.Exit(0)
		}
		showConfigHelp()
	}
}

func doCmdKey() {
	args := os.Args
	if len(args) > 1 && args[1] == "key" {
		if len(args) > 2 && args[2] == "create" {
			if len(args) == 5 {
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

				cfg, err := config.LoadFromInteractive(filename)
				panicOnErr(err)
				key, err := cfg.CreateAndAddKey(keyType, strconv.FormatInt(cfg.NextSequentialKeyCN(), 10))
				panicOnErr(err)
				if cfg.PreferredKeyCN == "" {
					cfg.PreferredKeyCN = key.CN
				}
				panicOnErr(cfg.SaveTo(filename))
				fmt.Println("Key generated with keyId", key.Uuid, "and CN", key.CN)
				os.Exit(0)
			} else {
				showKeyCreateHelp()
			}
		}
		if len(args) == 5 && args[2] == "delete" {
			uuid := args[3]
			filename := args[4]
			cfg, err := config.LoadFromInteractive(filename)
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
			cfg, err := config.LoadFromInteractive(args[3])
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
		if len(args) == 5 && args[2] == "export" {
			cfg, err := config.LoadFromInteractive(args[4])
			fullKey := args[3][0:5] == "full@"
			pubKey := args[3][0:4] == "pub@"
			if !fullKey && !pubKey {
				fmt.Println("invalid key format, it should be i.e. full@1 or pub@2")
				os.Exit(1)
			}
			keyNo, err := strconv.ParseInt(args[3][strings.Index(args[3], "@")+1:], 10, 16)
			panicOnErr(err)
			for n, key := range cfg.Keys {
				if n+1 == int(keyNo) {
					if pubKey {
						key.Pvt = ""
					}
					jsonb, err := json.MarshalIndent(key, "", "  ")
					panicOnErr(err)
					fmt.Println(string(jsonb))
				}
			}
			os.Exit(0)
		}
		if len(args) == 4 && args[2] == "import" {
			cfg, err := config.LoadFromInteractive(args[3])
			panicOnErr(err)
			key := config.Key{}
			bytes, err := ioutil.ReadAll(os.Stdin)
			panicOnErr(err)
			panicOnErr(json.Unmarshal(bytes, &key))
			if key.Pub == "" || key.Type == "" {
				panicOnErr(errors.New("it does not look like a key"))
			}
			for cfg.DeleteKeyByUUID(key.Uuid) {
			}
			cfg.Keys = append(cfg.Keys, key)
			if cfg.PreferredKeyCN == "" {
				cfg.PreferredKeyCN = key.CN
			}
			panicOnErr(cfg.SaveTo(args[3]))
			os.Exit(0)
		}
		showKeyHelp()
	}
}

func doCmdPotp() {
	args := os.Args
	if len(args) > 1 && args[1] == "potp" {
		if len(args) > 2 && args[2] == "create" {
			if len(args) == 5 {
				potpSize, err := strconv.ParseInt(args[3], 10, 32)
				panicOnErr(err)
				if potpSize < 64 || potpSize > 64*1024 {
					err = errors.New("potp should be between 64 bytes and 64 kbytes")
					panicOnErr(err)
				}
				filename := args[4]
				cfg, err := config.LoadFromInteractive(filename)
				panicOnErr(err)
				potp, err := cfg.CreateAndAddInPlacePotp(int(potpSize), strconv.FormatInt(cfg.NextSequentialPotpCN(), 10))
				panicOnErr(err)
				if cfg.PreferredPotpCN == "" {
					cfg.PreferredPotpCN = potp.CN
				}
				err = cfg.SaveTo(filename)
				panicOnErr(err)
				fmt.Printf("potp of %v bytes created, with uuid %v and CN %v\n", potpSize, potp.Uuid, potp.CN)
				os.Exit(0)
			} else {
				showPotpCreateHelp()
			}
		}
		if len(args) == 5 && args[2] == "export" {
			cfg, err := config.LoadFromInteractive(args[4])
			potpNo, err := strconv.ParseInt(args[3][1:], 10, 16)
			panicOnErr(err)
			for n, key := range cfg.Potps {
				if n+1 == int(potpNo) {
					jsonb, err := json.MarshalIndent(key, "", "  ")
					panicOnErr(err)
					fmt.Println(string(jsonb))
				}
			}
			os.Exit(0)
		}
		if len(args) == 4 && args[2] == "import" {
			cfg, err := config.LoadFromInteractive(args[3])
			panicOnErr(err)
			potp := config.Potp{}
			bytes, err := ioutil.ReadAll(os.Stdin)
			panicOnErr(err)
			panicOnErr(json.Unmarshal(bytes, &potp))
			if potp.Body == "" {
				panicOnErr(errors.New("it does not look like a potp"))
			}
			for cfg.DeletePotpByUUID(potp.Uuid) {
			}
			cfg.Potps = append(cfg.Potps, potp)
			if cfg.PreferredPotpCN == "" {
				cfg.PreferredPotpCN = potp.CN
			}
			panicOnErr(cfg.SaveTo(args[3]))
			os.Exit(0)

		} else {
			showPotpHelp()
		}
		os.Exit(0)
	}
}
func panicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}

func showGeneralHelp() {
	fmt.Println(`Post Quantum Secure Wire Configuration Tool 

Usage:

         pqswcfg <command> [arguments]

The commands are:

         config	   manages configuration files
         key       manages keys in the key store, including creation.
         potp      manages pragmatic one-time-pads
         uniq      manages unique ids memories

Use "pqswcfg help <command>" for more information about a command.`)
	os.Exit(0)
}

func showConfigHelp() {
	fmt.Println(`Usage: config <sub command> <configuration file>

The Sub commands are:
         create    creates an empty new configuration file
         encrypt   encrypts the configuration file with a text password (or changes its password)
         decrypt   removes the encryption from the configuration file
         vanilla   creates a new configuration file with typical defaults
         show      loads a configuration file and shows details
         verify    verifies its contents are coherent and valid`)
	os.Exit(0)
}

func showKeyHelp() {
	fmt.Println(`

Usage: 

         pqswcfg key <command> [arguments]

The commands are:

         create    creates a new key and adds it to the store
         delete    deletes a key
         list      list all the keys
         import    imports a key
         export    exports a key`)
	os.Exit(0)
}

func showKeyCreateHelp() {
	fmt.Println("Usage: pqswcfg key create <type> <config file>")
	fmt.Println("\nSupported key types: ")
	values := make([]string, 0, len(cryptoutil.KeyTypeAsString))
	for _, v := range cryptoutil.KeyTypeAsString {
		values = append(values, v)
	}
	sort.Strings(values)
	first := values[0][0]
	fmt.Print("- ")
	for _, v := range values {
		if v[0] != first {
			first = v[0]
			fmt.Print("\n- ")
		}
		fmt.Print(v, " ")
	}
	fmt.Println()
	os.Exit(0)
}

func showKeyDeleteHelp() {
	fmt.Println("Usage: pqswcfg key delete <key id> <config file>")
}

func showPotpHelp() {
	fmt.Println(`

Usage:

         pqswcfg potp <command> [arguments]

The commands are:

         create    creates a new potp of size in bytes provided
         delete    deletes a potp
         export    exports a potp
         import    imports a potp
         list      lists all potps`)
}

func showPotpCreateHelp() {
	fmt.Println("Usage: pqswcfg potp create <byte-size> <config file>")
}
