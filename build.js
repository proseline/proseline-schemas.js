var crypto = require('@proseline/crypto')
var strictObjectSchema = require('strict-json-object-schema')

var publicKey = hexString(crypto.signingPublicKeyBytes)
var signature = hexString(crypto.signatureBytes)
var nonce = hexString(crypto.nonceBytes)

// Schemas represent byte strings as hex strings.
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

// JSON Schemas reused below:

var project = hexString(crypto.hashBytes)
var digest = hexString(crypto.hashBytes)

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

// Inner Envelopes contain signatures, a link to the prior
// log entry, and the message.
var innerEnvelope = {
  type: 'object',
  properties: {
    logSignature: signature,
    clientSignature: signature, // optional
    projectSignature: signature,
    prior: digest, // optional
    message: {
      oneOf: [ correction, draft, intro, mark, note, reply ]
    }
  },
  required: [
    'logSignature',
    'projectSignature',
    'message'
  ],
  additionalProperties: false
}

innerEnvelope.title = 'inner envelope'

// Outer Envelopes enclose encrypted Inner Envelopes,
// exposing just enough data to allow replication-only
// peers that know the replication key to replicate data.
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
          ')?' +
        '$'
      )
    })()
  }
})

outerEnvelope.title = 'outer envelope'

// References point to particular log entries by log public
// key and integer index. Peers exchange references to offer
// and request log entries.
var reference = strictObjectSchema({
  publicKey: publicKey,
  index: { type: 'integer', minimum: 0 }
})

reference.title = 'reference'

// Invitations transmit replication keys, as well as
// encrypted read and write keys, for use and storage
// by account servers.
var invitation = {
  type: 'object',
  properties: {
    replicationKeyCiphertext: hexString(
      crypto.projectReplicationKeyBytes +
      crypto.encryptionMACBytes
    ),
    replicationKeyNonce: nonce,
    readKeyCiphertext: hexString(
      crypto.projectReadKeyBytes +
      crypto.encryptionMACBytes
    ),
    readKeyNonce: nonce,
    writeSeedCiphertext: hexString(
      crypto.signingKeyPairSeedBytes +
      crypto.encryptionMACBytes
    ), // optional
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

invitation.title = 'invitation'

module.exports = {
  invitation: invitation,
  reference: reference,
  innerEnvelope: innerEnvelope,
  outerEnvelope: outerEnvelope
}
