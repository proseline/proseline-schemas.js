var sodium = require('sodium-universal')
var strictObjectSchema = require('strict-json-object-schema')

var NONCE_BYTES = sodium.crypto_secretbox_NONCEBYTES
var SIGN_BYTES = sodium.crypto_sign_BYTES
var SIGN_PUBLICKEYBYTES = sodium.crypto_sign_PUBLICKEYBYTES

var publicKey = hexString(SIGN_PUBLICKEYBYTES)

var signature = hexString(SIGN_BYTES)

var nonce = hexString(NONCE_BYTES)

// Schemas represent byte strings as hex strings.
function hexString (bytes) {
  var returned = {
    title: 'hexadecimal string',
    type: 'string',
    pattern: '^[a-f0-9]+$'
  }
  if (bytes) returned.length = bytes
  return returned
}

var GENERICHASH_BYTES = sodium.crypto_generichash_BYTES

// JSON Schemas reused below:

var project = hexString(GENERICHASH_BYTES)
var digest = hexString(GENERICHASH_BYTES)
var timestamp = { title: 'timestamp', type: 'string', format: 'date-time' }
var name = { title: 'name', type: 'string', minLength: 1, maxLength: 256 }
var noteText = { title: 'note text', type: 'string', minLength: 1 }

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
    maxItems: 2,
    uniqueItems: true
  },
  text: { type: 'object' },
  timestamp: timestamp
})

draft.title = 'draft'

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

mark.title = 'mark'

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

note.title = 'note'

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

reply.title = 'reply'

// Corrections update the text of notes.
var correction = strictObjectSchema({
  type: { const: 'correction' },
  note: digest,
  text: noteText,
  timestamp: timestamp
})

correction.title = 'correction'

// Notes associates names and device, like "Kyle on laptop"
// with logs.
var intro = strictObjectSchema({
  type: { const: 'intro' },
  name: name,
  device: name,
  timestamp: timestamp
})

intro.title = 'intro'

var messages = { correction, draft, intro, mark, note, reply }

var innerEnvelope = {
  type: 'object',
  properties: {
    logSignature: signature,
    clientSignature: signature, // optional
    projectSignature: signature,
    prior: digest, // optional
    message: { oneOf: Object.values(messages) }
  },
  required: [
    'logSignature',
    'projectSignature',
    'message'
  ],
  additionalProperties: false
}

innerEnvelope.title = 'inner envelope'

var outerEnvelope = strictObjectSchema({
  project: project,
  publicKey: publicKey,
  index: { type: 'integer', minimum: 0 },
  nonce: nonce,
  encryptedInnerEnvelope: {
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
          ')' +
        '$'
      )
    })()
  }
})

outerEnvelope.title = 'outer envelope'

// References

// References point to particular log entries by log public
// key and integer index. Peers exchange references to offer
// and request log entries.
var reference = strictObjectSchema({
  publicKey: publicKey,
  index: { type: 'integer', minimum: 0 }
})

reference.title = 'reference'

var invitation = {
  type: 'object',
  properties: {
    replicationKeyCiphertext: hexString(96),
    replicationKeyNonce: nonce,
    readKeyCiphertext: hexString(96),
    readKeyNonce: nonce,
    writeSeedCiphertext: hexString(96), // optional
    writeSeedNonce: nonce, // optional
    titleCiphertext: hexString(), // optional
    titleNonce: nonce // optional
  },
  required: [
    'replicationKeyCiphertext',
    'replicationKeyNonce',
    'readKeyCiphertext',
    'readKeyNonce'
  ],
  additionalProperties: false
}

module.exports = {
  // messages: messages,
  invitation: invitation,
  reference: reference,
  innerEnvelope: innerEnvelope,
  outerEnvelope: outerEnvelope
}
