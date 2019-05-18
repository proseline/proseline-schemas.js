# @proseline/schemas

JSON schemas for Proseline data messages

## JavaScript Module

```javascript
var schemas = require('@proseline/schemas')
var assert = require('assert')

assert(typeof schemas.reference === 'object')
assert(typeof schemas.innerEnvelope === 'object')
assert(typeof schemas.outerEnvelope === 'object')
assert(typeof schemas.invitation === 'object')
```

## Schema Overview

```
+----------------------------------------------------------+
| Outer Envelope                                           |
| - project discovery key                                  |
| - log public key                                         |
| - log entry index                                        |
| - random inner envelope encryption nonce                 |
| +------------------------------------------------------+ |
| | Inner Envelope (encrypted with project shared key)   | |
| | - signature with log keypair                         | |
| | - signature with project write keypair               | |
| | - (optional) signature with client keypair           | |
| | - (optional) digest of prior log entry               | |
| | +--------------------------------------------------+ | |
| | | Message (JSON, keys sorted)                      | | |
| | | One Of:                                          | | |
| | | - draft                                          | | |
| | | - mark                                           | | |
| | | - log author introduction                        | | |
| | | - note to a draft                                | | |
| | | - reply to a note                                | | |
| | | - correction to a note or reply                  | | |
| | +--------------------------------------------------+ | |
| +------------------------------------------------------+ |
+----------------------------------------------------------+
```
