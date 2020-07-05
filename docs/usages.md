# Usage examples

## PQSWTUN: Tunnelling HTTPS via a Post-Quantum cryptographically secure channel

### Creating configuration files holding keys and a potp
You will need two configurations files, `server.conf` and `client.conf`. Each one will have a full key (with a private
and public part, and the counter-party public only key). They will also have a common shared secret (the pragmatic
one-time-pad).

For creating the server configuration file:
```
$ bin/pqswcfg config create server.conf
$ bin/pqswcfg key create SIKE_FP751 server.conf
$ bin/pqswcfg potp create 1024 server.conf 
```

For the client configuration:
```
$ bin/pqswcfg config create client.conf
$ bin/pqswcfg key create SIKE_FP751 client.conf
```

Then, we export the public key from the server into the client, and vice-versa.
```
$ bin/pqswcfg key export pub@1 server.conf | bin/pqswcfg key import client.conf
$ bin/pqswcfg key export pub@1 client.conf | bin/pqswcfg key import server.conf
```

... and the POTP generated in the server config, to the client:
```
$ bin/pqswcfg potp export @1 server.conf | bin/pqswcfg potp import client.conf
```

(It can be instructive to `$ cat server.conf` and `$ cat client.conf` to understand how the configuration files are in
fact JSON files with base64 encoded strings)

### Starting and using the tunnel 
(in two different terminals)
```
$ bin/pqswtun -c server.conf exit   4444:yahoo.com:443
$ bin/pqswtun -c client.conf entry  localhost:8443:localhost:4444
```

The 'entry' or 'client' service listens for plain-text traffic, when a connection is received on port 8443, it will
connect to localhost:4444, and try to establish a post-quantum cryptographically secure channel using pqsw, on success,
the exit node will contact yahoo.com on port 443, and forward the traffic until disconnects.

Therefore, you can try it by doing: `$ curl --insecure https://localhost:8443/`

## Practical example: Encapsulating SSH
Instead of running both entry and exit tunnel nodes in the same machine, what a user would probably want to achieve
is to run the server in a remote host, and the client in the local machine, effectively handling the transport security
to the tunnel. i.e. SSH tunnels. 

The following commands would encapsulate a ssh session within a pqsw secure wire.
``` 
(remote)$ pqswtun -c server.conf exit  4444:localhost:22
 (local)$ pqswtun -c client.conf entry localhost:2222:remote:4444
 (local)$ ssh localhost -p 2222
```

## Comment on the key distribution problem
The `server.conf` file needs to be copied into the remote server. If the user "really" wants to be post-quantum safe,
the file should not be transferred with non-quantum safe cryptography. i.e. current `ssh` or `scp` implementations. 
This issue is at the moment, to the best of our knowledge, theoretical.
