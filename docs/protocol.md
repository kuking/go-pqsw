# PQSW Protocol  

| Direction | Description                                                                                             |
|-----------|---------------------------------------------------------------------------------------------------------|
| Cli->Srv  | Establishes connection                                                                                  |
| Srv->Cli  | "Please solve this Puzzle first. i.e. sha512 leading n zeros"                                           |
| Cli->Srv  | "Responses the challenge"                                                                               |
| Cli->Srv  | "Hello, this is my key-id, I intend to use the following protocol version, wire type"                   |
|  Server   | Checks if key-id is whitelisted, protocol version, and wire type.                                       |
| Srv->Cli  | "Using my key-id, please provide shared secret, otp id and offset"                                      |
|  Client   | Checks if the key-id is whitelisted. Generated a random secret and signs it.                            |
| Cli->Srv  | "This is my shared secret, potp-id and offset."                                                         |
|  Server   | Decodes the shared secret, this step might fail on invalid potp-id/offset,                              |
| Srv->Cli  | "This is my shared secret. popt-id and offset."                                                         |
|  Client   | Decodes the shared secret, as previous step by server.                                                  |
|   both    | Establish secure connection using both parties shared secrets an potps                                  |

After the last step, both parties have enough secrets to create the CGM streams. The amount of shared keys to send
and shared secrets to use follows the logic below:
- Given kemSize (128 for Fp503, 192 for Fp751), aesKeySize(256 or 768 for TripleAES256), halfAESKeySize = aesKeySize/2
- kems to send: halfAESKeySize/kemSize (+1 if halfAESKeySize % kemSize > 0)
- potp to use: halfAESKeySize

Finally, the AES-256 keys are derived using: Server shared secret + Client shared secret + Server POTP bytes + Client
POTP bytes, mixing one byte of each in the mentioned order. If the byte output required for building all the required
keys is smaller, it will overlap and keep applying the input bytes XORing them with the previous value, until all the
secret bytes are exhausted.

If a triple-AES256 is used, the final stream cipher will be built as three encapsulated GCM streams:
`GCM(K1, (GCM(K2, (GCM(K3, insecure wire)))))`

Practical comments: Current implementation using SIDH provides 192 bits of entropy, for Triple-AES256, two shared 
secrets are required by both parties (256*3=768 = 192 * 2 times * 2 parties). In the case of Simple-AES256, one shared
secret per client/server would be enough.

