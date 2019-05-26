# @proseline/schemas

JSON schemas for Proseline data messages

## JavaScript Module

```javascript
var schemas = require('@proseline/schemas')
var assert = require('assert')

assert(typeof schemas.entry === 'object')
assert(typeof schemas.envelope === 'object')
assert(typeof schemas.invitation === 'object')
assert(typeof schemas.reference === 'object')
```

## Overview

### Envelope

```
+----------------------------------------------------------+
| Envelope                                                 |
| + JSON-encoded                                           |
| + sent via channel encrypted with replication key        |
|                                                          |
| - project discovery key                                  |
| - log public key                                         |
| - signature with log secret key                          |
| - signature with project shared key                      |
| - log entry index (>= 0)                                 |
| - random inner envelope encryption nonce                 |
|                                                          |
| +------------------------------------------------------+ |
| | Entry                                                | |
| | + keys sorted                                        | |
| | + JSON-encoded                                       | |
| | + encrypted with project public key                  | |
| | + Base64-encoded                                     | |
| |                                                      | |
| | - log entrty index (>= 0)                            | |
| | - digest of prior log entry (log entry index > 0)    | |
| |                                                      | |
| | One Of:                                              | |
| | - draft                                              | |
| | - mark                                               | |
| | - log author introduction                            | |
| | - note to a draft                                    | |
| | - reply to a note                                    | |
| | - correction to a note or reply                      | |
| |                                                      | |
| +------------------------------------------------------+ |
+----------------------------------------------------------+
```

## Invitation

```
+----------------------------------------------------------+
| Invitation                                               |
|                                                          |
| Required:                                                |
| - project replication key                                |
| - project public key                                     |
|                                                          |
| Optional:                                                |
| - encrypted project secret key (optional)                |
| - project secret key encryption nonce                    |
| - encrypted project read key                             |
| - project read key encryption nonce                      |
| - encrypted project title                                |
| - project title encryption nonce                         |
|                                                          |
+----------------------------------------------------------+
```
