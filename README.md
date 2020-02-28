# SIKE_protocol
SIKE_protocol is a protocol for establishing connections based on Supersingular Isogeny Key Encapsulation (SIKE) and AES.

# SIKE
The used implementation of SIKE is PQCrypto-SIDH from Microsoft at https://github.com/microsoft/PQCrypto-SIDH.git

# AES
The used implementation of AES is tinyAES from kokke at https://github.com/kokke/tiny-AES-c.git

# Build demonstration
Clone this repository using `git clone --recursive https://github.com/Jonas-July/SiKE_protocol.git` or similar
`cd` into the directory
Run `./gen`. This will automatically build the executable.

The resulting demonstration of the protocol can be run with `./prot`
