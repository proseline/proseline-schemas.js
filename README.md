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

## Overview

```
+----------------------------------------------------------+
| Outer Envelope                                           |
| + JSON-encoded                                           |
| + sent via channel encrypted with replication key        |
|                                                          |
| - project discovery key                                  |
| - log public key                                         |
| - log entry index                                        |
| - random inner envelope encryption nonce                 |
|                                                          |
| +------------------------------------------------------+ |
| | Inner Envelope                                       | |
| | + keys sorted                                        | |
| | + JSON-encoded                                       | |
| | + encrypted with project shared key                  | |
| | + Base64-encoded                                     | |
| |                                                      | |
| | - signature with log keypair                         | |
| | - signature with project write keypair               | |
| | - digest of prior log entry (log entry index > 0)    | |
| | - (optional) signature with client keypair           | |
| |                                                      | |
| | +--------------------------------------------------+ | |
| | | Message                                          | | |
| | | + keys sorted                                    | | |
| | | + JSON-encoded                                   | | |
| | |                                                  | | |
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

Invitations, which include unencrypted replication keys,
allow super peers to read and retransmit outer envelopes.

Peers with project read keys can open inner envelopes and
read the messages they contain.

Peers with project write keys can generate log key pairs
and sign messages containing entries.
