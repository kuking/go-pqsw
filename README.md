# Post Quantum Secure Wire
Implementation in Go language of a secure-wire, using safe post-quantum cryptography. It has a simple and light 
key-agreement protocol which includes some future proof features. i.e. client puzzle challenge, pragmatic one-time-pad, 
triple AES-256 (more on this later), KEM SIDH Sike using up to Fp751 curves, etc. 

Implementation is well tested with a minimal attack surface, if the used cryptographic primitives and the integrations 
decisions are to be trusted, it is safe to say pqsw can be put forward into a strict crypto analysis.

For details on the key-agreement protocol and some technical decisions, please read the
[cryptographic details and implementation document](docs/crypto-and-technical.md) (you will also find the main features
and attack prevention mechanisms in both the cryptographic protocol design and implementation). Please find the protocol
message details [in the protocol document](docs/protocol.md).

The  easiest way to try this, is to use the tool `pqswtun` which can be used to establish a tunnel like in the command
`ssh -L`, it has to be run twice in two different modes, entry and exit node. i.e. 
`(local)$ pqswtun entry localhost:2222:remote:4444` &  `(remote)$ pqswtun exit 4444:localhost:22`. 
Please read in more detail the [pqswtun documentation](docs/pqswtun.md).

Finally, the secure-wire is driven by a configuration file holding keys, potps, etc. please find its details in the
[pqswcfg documentation](docs/pqswcfg.md)

##  Author
Eduardo E.S. Riccardi, you can contact me via [linkedin](https://uk.linkedin.com/in/kukino), or you could find my email
address [here](https://kukino.uk/ed@kukino.uk.pub).

I am a crypto-enthusiast. For feedback and bug-fixes: you are probably right if you found a crypto mistake here.
I claim no expertise, no PhD in Mathematics, or 25 years of experience in cryptography, nor I give any warranty implicit
or explicit. After all disclaimers given, I would be happy to fix this, if broken, so your feedback is welcome.
But absolutelly no warranty is given of any kind, form or type.

## Todo
- File based potps
- Potps and Kem replay prevention (minor crypto implication as both parties choose a potp and kems)
- Increment puzzle difficulty on auth failure
- Demo golang program
- More tutorials
- Kill signal to reload config
- Triple AES256