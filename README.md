# PyOracle2

https://blog.liquidsec.net/2020/11/30/introducing-pyoracle2/

A python-based padding oracle tool.

Although several other padding oracle attack tools exist, some quite excellent, there are relatively few written in python. This tool provides another take on attacking padding oracle vulnerabilities with a handful of less common advanced features. 

Special Features:

- **Fault Tolerance** - Can handle some random bad requests (performs sanity check and will redo a block result that doesn’t make sense)
- **Resume feature** - Can be stopped and resumed at will (State of the operation is serialized and stored to disk!)
- **HTTP Proxy Support**
- **Positive and negative oracle searching** - can look for a special string to identify a successful request, and optionally the lack of a string
- **Multiple IV modes** - Supports first block IV (most common), last block IV, or known IV.

Planned improvements:

- Different encoding modes (only base64 is supported currently, although this is definately the most common)
- Ability to operate inside of XML parameters and JSON variables
- Support for timing-based oracles



```
usage: pyOracle2.py [-h] [-r RESTORE] [-i INPUT] [-m MODE] [-d] [-c CONFIG]

optional arguments:
  -h, --help            show this help message and exit
  -r RESTORE, --restore RESTORE
                        Specify a state file to restore from
  -i INPUT, --input INPUT
                        Specify either the ciphertext (for decrypt) or
                        plainttext (for encrypt)
  -m MODE, --mode MODE  Select encrypt or decrypt mode
  -d, --debug           increase output verbosity
  -c CONFIG, --config CONFIG
                        Specify the configuration file
```

pyOracle2 is designed around the creation of a configuration file for each unique "job". The goal is to frontload the configuration of the job so that once it is set correctly, exploitation can occur as easily as possible with a concise CLI command. A sample of the configuration file is provided.


Config file example:
```
[default]

# Job NameError
name = Name

# Specifiy the target URL
URL = http://127.0.0.1/index.php

# Specify the HTTP method (GET or POST)
httpMethod = GET

# specify the input mode (parameter, body, cookie)
inputMode = cookie

# Specify the parameter which contains the vulnerable variable
vulnerableParameter = auth

# Additional Parameters (specified in a dictionary as a key/value pair). Be sure to use double quotes. 
additionalParameters = {}

# Set the blocksize for the target
blocksize = 8

# Enable / Disable http proxy for outgoing traffic
httpProxyOn = True
httpProxyIp = 127.0.0.1
httpProxyPort = 8080

# Specifiy headers to add to the request (specified in a dictionary as a key/value pair)

headers = {"User-Agent":"Mozilla/5.0"}

# Specify Cookies to add to the request (specified in a dictionary as a key/value pair)
cookies = {}

# Specify the IV mode

# In most implementations, the IV is provided as the 'first block' of the ciphertext. 
# In other cases, the IV may be kept a known secret by both endpoints. In such a case, it should still be possible to decrypt everything but the first block.
# The IV may also be a static values such as all zeroes.

# Modes: 

# 'firstblock'. This mode assumes that the first block of the ciphertext is the IV (most common)
# 'knownIV'. This mode allows for user provided IV
# 'unknown'. Use this mode when you do not know the IV and it is not the first block but still wish to decrypt all but the first block, or re-encrypt all but the first block for encryption
# 'lastblock'. This has not been implemented yet, but it may be in the future as it is a rare but possible configuration


# choose from one of the above modes
ivMode = firstblock
# If using knownIV mode, specify the IV
#IV should be in decimal list format. For example: [72,65,82,65,77,66,69]
iv =  [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

# The oracle defines the information leak that is abused to know when padding is valid. This is typically an error message.
# There are several trigger modes depending on the situation. Sometimes you will want to look for a specific phrase, other times you want to look for an absence of that phrase. 

# trigger modes:
# 'search' - simply look for a specific phrase
# 'negative' - the opposite of search. Trigger when you don't see the phrase
oracleMode = negative

# Define the search phrase to look for from the oracle
oracleText = Invalid padding
```
