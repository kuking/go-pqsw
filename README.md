# Post Quantum Secure Wire
Implementation in Go language of a secure-wire, using safe post-quantum cryptography. It has a simple and light 
key-agreement protocol which includes some future proof features. i.e. client puzzle challenge, pragmatic one-time-pad, 
triple AES-256 (more on this later), FrodoKEM & SIDH Sike. 

__Usages:__ Drop-in replacement for ssh/ssl tunnels and TLS connections. Can be useful if you want to build a service
and would prefer to avoid TLS, or if you want to tunnel an existing service via a post-quantum secure channel (see 
author's disclaimer below). Quick [usage walkthrough here](docs/usages.md).

For details on the key-agreement protocol and some technical decisions, please read the
[cryptographic details and implementation document](docs/crypto-and-technical.md) (you will also find the main features
and attack prevention mechanisms in both the cryptographic protocol design and implementation). Please find the protocol
message details [in the protocol document](docs/protocol.md).

The  easiest way to try this, is to use the tool `pqswtun` which can be used to establish a tunnel like in the command
`ssh -L`. Please read in more detail the [pqswtun documentation](docs/pqswtun.md). Finally, the secure-wire is driven by
a configuration file holding keys, potps, etc. please find its details in the [pqswcfg documentation](docs/pqswcfg.md).

Post Quantum Ciphers supported so far:
- FrodoKEM (640, 976, 1344 in both AES and Shake variants).
- Sike (Fp434, Fp503 & Fp751)
- Kyber (soon)


##  Author
Eduardo E.S. Riccardi, you can contact me via [linkedin](https://uk.linkedin.com/in/kukino), or you could find my email
address [here](https://kukino.uk/ed@kukino.uk.pub).

I am a crypto-enthusiast. For feedback and bug-fixes: you are probably right if you found a crypto mistake here.
I claim no expertise, no PhD in Mathematics, or 25 years of experience in cryptography. I would be happy to fix this,
your feedback is welcomed. Absolutely no warranty of any kind, form or type is given, implicitly or explicitly.

## Todo
- File based potps
- Potps and Kem replay prevention (minor crypto implication as both parties choose a potp and kems)
- Increment puzzle difficulty on auth failure
- Demo golang program
- Kill signal to reload config
- Triple AES256