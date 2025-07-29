# Post Quantum Secure Wire
Implementation in Go language of a secure-wire (like TLS) using safe post-quantum cryptography. It has a simple and light 
key-agreement protocol which includes some future proof features. i.e. client puzzle challenge, pragmatic one-time-pad, 
triple AES-256 (more on this later), FrodoKEM, Kyber & SIDH Sike. 

### Usages
- `bin/pqswtun`: Drop-in replacement for ssh/ssl tunnels and TLS connections.
- `bin/pqswpat`: Broadcast server and client, can be used to build zero-knowledge servers. i.e. a chat
- As a library: Can be useful if you want to build a service and would prefer to avoid TLS.

Some [usage walkthroughs and examples here](docs/usages.md).

### Key agreement protocol
For details on the key-agreement protocol and some technical decisions, please read the
[cryptographic details and implementation document](docs/crypto-and-technical.md) (you will also find the main features
and attack prevention mechanisms in both the cryptographic protocol design and implementation). Please find the protocol
message details [in the protocol document](docs/protocol.md).


### Post-Quantum Ciphers supported
- FrodoKEM (640, 976, 1344 in both AES and Shake variants).
- ML Kem, Kyber (768, 1024) Using `crypto/mlkem`

##  Author
Eduardo E.S. Riccardi, you can contact me via [linkedin](https://uk.linkedin.com/in/kukino), or you could find my email
address [here](https://kukino.uk/ed@kukino.uk.pub).

I am a crypto-enthusiast. For feedback and bug-fixes: you are probably right if you have found a crypto mistake here.
I claim no expertise, no PhD in Mathematics, or 25 years of experience in cryptography. I would be happy to fix this,
your feedback is welcomed. Absolutely no warranty of any kind, form or type is given, implicitly or explicitly.

## Todo
- File based potps
- Increment puzzle difficulty on auth failure
- Kill signal or file change detection to reload config
- Potps offset can be any uint64, then it is % its size, to hide its real size.

# Changelog
- 2025/July/28: 
  - Removed Sike (not secure anymore)
  - Replaced Circl library for `crypto/mlkem`
  - Incremented scrypt difficulty to current CPUs power
