# Agginym Key Utility

The Agginym Key Utility is a barebones libsodium powered project to sign, verify, encrypt and decrypt various things. It works on files and text.

```
Agginym Key Utility, manage agginym key actions.  Create, sign, verify, encrypt, decrypt, inspect.

Configs are json files {"name":"Jeff", "publicKey":"", "privateKey":""}
input is a string or file, output is a string or file depending on the selected options.
All inputs are expected to be url-safe base64 encoded with no padding.  All outputs are url-safe base64 encoded with no padding.
Only one action is allowed at a time so just call it again with your output if you need to do more complicated stuff

Usage: 

      --help        - You'll get this message.

      --create      - Creates a new json key pair.  The string directly after create is treated as the new name. No other commands will run if this is defined.
                      --create [name]

      --inspect     - This is used to inspect any key or keypair specified.  No other commands will run if this is defined.
                      Either --file or --key is required but only one at a time.   **NOTE** ONLY THE PUBLIC KEY SHOULD EVER BE SHARED.  Seriously, don't share the whole thing. Just copy and paste the thing publicKey.
                      --inspect --file [keypair.json], or --inspect --key [private or publickey string]

      --fingerprint - This prints the fingerprint of the key.  Requires either --key or --keypair.  It's a base58 representation.  Only works with a public key
                      Hex is too long even though it survives capitalization. Base64 can be somewhat confusing sometimes.  
                      --fingerprint --key [publicKeyString]

      --decrypt     - Decrypt a string of text. Requires --key or --keypair.  The string immediately after --decrypt is taken as the input.
                      If --file is used then the file is used as input. If there is nothing afterwards or just another option specified then it takes piped or whatever input.
                      --decrypt [base64 string] --key [privateKeyString] --file 

      --encrypt     - Encrypt a string of text.  Requires --key.  The string immediately after --encrypt is taken as the input.  Requires quotes for items with spaces.
                      If --file is used then the file is used as input.  If there is nothing afterwards or just another option specified then it takes piped or whatever input.
                      --encrypt [raw string]  --key [publicKeyString]

      --sign        - Outputs a signed text or file for the provided input.  Base64 encoding with no padding. if --detached is defined then it only outputs the signature
                      --sign [string] --key [privateKey string] (--detached), or --sign --file [somefile.jpg/txt/whatever] --key [privateKey string] (--detached)

      --verify      - Verifies a detached signature and file/text or a combined signed file. Requires --signature and --key
                      --verify [string] --key [publicKey string] (--signature), or --verify --file [somecoolfile.png/pdf/whatever] --key [publicKey string] (--signature)

      --detached    - States whether a signature is detached or not while signing or verifying.  Only has any effect with --sign

      --signature   - The signature you need to provide when you specify --detached and --verify

      --key         - This is the public key when used with --verify or --encrypt. This is the private key when --sign or --decrypt.

      --file        - This is the input file when doing anything with --verify, --encrypt --decrypt, --inspect, or --fingerprint

      --signature   - This is the signature for use with --decrypt when --verify and --detached are used together

      --output      - This is the output file when doing anything with --encrypt or --decrypt.  If it's not specified then output is to stdout

      --debug,loud  - This prints a bunch of information that may be helpful in finding bugs.

      --force       - If the file exists this will truncate and write to the output file if --output is specified.
                      If --force is not specified and the file exists it will print to console.

      Input streams are not supported right now.  Bug reports are welcome.  I hope you're having a good day.
```

## Installation
```
git clone github.com/anidean/agginym-cli
cd agginym-cli
git submodule init
git submodule update
cd libsodium
git checkout stable
./configure
make -j && make -j check
make install
cd ../fmt
mkdir build && cd build
cmake ..
make -j
cp libfmt.a ../../libs
cd ../..
make
```

That's quite a few steps but it should be pretty smooth.  You may need other libraries to get those dependencies working. 

It has only been hand tested on Ubuntu 18.04 with bash.  Bug reports, pull requests and suggestions are welcome.

### Be warned, the code has not been audited and is experimental software.  Do not use it if your safety depends upon it's security.

You may be able to draw some interesting comparisons between the usage of libsodium vs gpg utilities with the following two files:

[GPGME synchronous experimental code](https://gist.github.com/anidean/aaf803fdb68a2bc22994762d74a879d2)
[Sequoia PGP experimental code](https://gist.github.com/anidean/dc3b4dd75ae6259cfb317c2918950ca0)
