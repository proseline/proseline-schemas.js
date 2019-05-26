var crypto = require('@proseline/crypto')
var strictObjectSchema = require('strict-json-object-schema')

// JSON Schemas reused below:

var logPublicKey = hexString(crypto.signingPublicKeyBytes)
var signature = hexString(crypto.signatureBytes)
var nonce = hexString(crypto.nonceBytes)
var discoveryKey = hexString(crypto.hashBytes)
var digest = hexString(crypto.hashBytes)

function hexString (bytes) {
  var returned = {
    title: 'hexadecimal string',
    type: 'string',
    pattern: '^[a-f0-9]+$'
  }
  if (bytes) {
    var characters = bytes * 2
    returned.minLength = characters
    returned.maxLength = characters
  }
  return returned
}

var index = { type: 'integer', minimum: 0 }

var timestamp = {
  title: 'timestamp',
  type: 'string',
  format: 'date-time'
}

var name = {
  title: 'name',
  type: 'string',
  minLength: 1,
  maxLength: 256
}

var noteText = {
  title: 'note text',
  type: 'string',
  minLength: 1
}

// Log Entry Types

// Drafts store the contents of a written draft.
var draft = strictObjectSchema({
  type: { const: 'draft' },
  // A draft can be based on up to two parents:
  // other drafts on which the new draft was based.
  parents: {
    type: 'array',
    // Drafts reference parents by their digests.
    items: digest,
    // Drafts can have at most two parents.
    maxItems: 2,
    uniqueItems: true
  },
  text: { type: 'object' },
  timestamp: timestamp
})

// Marks record when a user moves a named marker onto a
// specific draft.
var mark = strictObjectSchema({
  type: { const: 'mark' },
  // Each identifier has a unique identifier. User may
  // change the names of identifiers over time.
  identifier: hexString(4),
  name: {
    type: 'string',
    minLength: 1,
    maxLength: 256
  },
  timestamp: timestamp,
  // Marks reference drafts by their digests.
  draft: digest
})

// Notes store comments to drafts, as well as replies to
// other notes.  This schema represents a note to a draft.
var note = strictObjectSchema({
  type: { const: 'note' },
  // Notes reference drafts by their digests.
  draft: digest,
  // The cursor position of the range of the draft to which
  // the note pertains.
  range: strictObjectSchema({
    start: { type: 'integer', minimum: 0 },
    end: { type: 'integer', minimum: 1 }
  }),
  text: noteText,
  timestamp: timestamp
})

// Replies are notes to other notes.
var reply = strictObjectSchema({
  type: { const: 'note' },
  draft: digest,
  // Unlike notes to draft, reply notes reference their
  // parent notes by digest, and do not specify ranges with
  // the draft.
  parent: digest,
  text: noteText,
  timestamp: timestamp
})

// Corrections update the text of notes.
var correction = strictObjectSchema({
  type: { const: 'correction' },
  note: digest,
  text: noteText,
  timestamp: timestamp
})

// Notes associates names and device, like "Kyle on laptop"
// with logs.
var intro = strictObjectSchema({
  type: { const: 'intro' },
  name: name,
  device: name,
  timestamp: timestamp
})

var entryTypes = { correction, draft, intro, mark, note, reply }

Object.keys(entryTypes).forEach(function (name) {
  var schema = entryTypes[name]
  schema.title = name
  schema.properties.prior = digest
  schema.properties.index = index
  schema.required.push('index')
  schema.required.sort()
})

var entry = {
  title: 'entry',
  oneOf: Object.keys(entryTypes).map(function (name) {
    return { '$ref': '#/definitions/' + name }
  }).sort(),
  definitions: entryTypes
}

// Envelopes enclose encrypted entries, exposing just enough
// data to allow replication-only peers that know the
// replication key to replicate data.
var envelope = strictObjectSchema({
  discoveryKey: discoveryKey,
  logPublicKey: logPublicKey,
  logSignature: signature,
  projectSignature: signature,
  index: index,
  nonce: nonce,
  encryptedEntry: {
    type: 'string',
    minLength: 4,
    pattern: (function makeBase64RegEx () {
      var CHARS = '[A-Za-z0-9+/]'
      return (
        '^' +
          '(' + CHARS + '{4})*' +
          '(' +
            CHARS + '{2}==' +
            '|' +
            CHARS + '{3}=' +
          ')?' +
        '$'
      )
    })()
  }
})

envelope.title = 'envelope'

// References point to particular log entries by log public
// key and integer index. Peers exchange references to offer
// and request log entries.
var reference = strictObjectSchema({
  logPublicKey,
  index: { type: 'integer', minimum: 0 }
})

reference.title = 'reference'

// Invitations transmit replication keys, as well as
// encrypted read and write keys, for use and storage
// by account servers.
var invitation = {
  title: 'invitation',
  type: 'object',
  properties: {
    replicationKey: hexString(crypto.projectReplicationKeyBytes),
    publicKey: hexString(crypto.signingPublicKeyBytes),
    // optional
    secretKey: strictObjectSchema({
      ciphertext: hexString(
        crypto.signingSecretKeyBytes +
        crypto.encryptionMACBytes
      ),
      nonce
    }),
    // optional:
    encryptionKey: strictObjectSchema({
      ciphertext: hexString(
        crypto.projectReadKeyBytes +
        crypto.encryptionMACBytes
      ),
      nonce
    }),
    // optional:
    title: strictObjectSchema({
      ciphertext: hexString(),
      nonce
    })
  },
  required: [
    'replicationKey',
    'publicKey'
  ],
  additionalProperties: false
}

module.exports = {
  invitation,
  reference,
  envelope,
  entry
}
