const assert = require('assert')
const crypto = require('@proseline/crypto')
const strictObjectSchema = require('strict-json-object-schema')

// JSON Schemas reused below:

const base64Pattern = (function makeBase64RegEx () {
  const CHARS = '[A-Za-z0-9+/]'
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

const logPublicKey = base64String(crypto.publicKeyBytes)
const signature = base64String(crypto.signatureBytes)
const nonce = base64String(crypto.nonceBytes)
const discoveryKey = base64String(crypto.digestBytes)
const digest = base64String(crypto.digestBytes)

function base64String (bytes) {
  if (bytes) {
    assert(Number.isSafeInteger(bytes))
    assert(bytes > 0)
  }
  const returned = {
    title: 'base64 string',
    type: 'string',
    pattern: base64Pattern
  }
  if (bytes) {
    const characters = Buffer.alloc(bytes).toString('base64').length
    returned.minLength = characters
    returned.maxLength = characters
  } else {
    returned.minLength = 4
  }
  return returned
}

const index = { type: 'integer', minimum: 0 }

const timestamp = {
  title: 'timestamp',
  type: 'string',
  format: 'date-time'
}

const name = {
  title: 'name',
  type: 'string',
  minLength: 1,
  maxLength: 256
}

const noteText = {
  title: 'note text',
  type: 'string',
  minLength: 1
}

// Log Entry Types

// Drafts store the contents of a written draft.
const draft = strictObjectSchema({
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
const mark = strictObjectSchema({
  type: { const: 'mark' },
  // Each identifier has a unique identifier. User may
  // change the names of identifiers over time.
  identifier: base64String(4),
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
const note = strictObjectSchema({
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
const reply = strictObjectSchema({
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
const correction = strictObjectSchema({
  type: { const: 'correction' },
  note: digest,
  text: noteText,
  timestamp: timestamp
})

// Notes associates names and device, like "Kyle on laptop"
// with logs.
const intro = {
  type: 'object',
  properties: {
    type: { const: 'intro' },
    name: name,
    device: name,
    timestamp: timestamp,
    email: { // optional
      type: 'string',
      format: 'email'
    },
    phone: { // optional
      type: 'string',
      pattern: '^\\+[0-9]+$'
    }
  },
  required: ['type', 'name', 'device', 'timestamp'],
  additionalProperties: false
}

const entryTypes = { correction, draft, intro, mark, note, reply }

Object.keys(entryTypes).forEach(function (name) {
  const schema = entryTypes[name]
  schema.title = name
  schema.properties.prior = digest
  schema.properties.index = index
  schema.properties.discoveryKey = discoveryKey
  schema.required.push('index', 'discoveryKey')
  schema.required.sort()
})

const entry = {
  title: 'entry',
  oneOf: Object.keys(entryTypes).map(function (name) {
    return { $ref: '#/definitions/' + name }
  }).sort(),
  definitions: entryTypes
}

// Envelopes enclose encrypted entries, exposing just enough
// data to allow replication-only peers that know the
// replication key to replicate data.
const envelope = {
  title: 'envelope',
  type: 'object',
  properties: {
    discoveryKey: discoveryKey,
    logPublicKey: logPublicKey,
    logSignature: signature,
    projectSignature: signature,
    index: index,
    prior: digest,
    entry: {
      nonce,
      ciphertext: base64String()
    }
  },
  required: [
    'discoveryKey',
    'logPublicKey',
    'logSignature',
    'projectSignature',
    'index',
    'entry'
  ],
  additionalProperties: false
}

// References point to particular log entries by log public
// key and integer index. Peers exchange references to offer
// and request log entries.
const reference = strictObjectSchema({
  logPublicKey,
  index: { type: 'integer', minimum: 0 }
})

reference.title = 'reference'

// Invitations transmit replication keys, as well as
// encrypted read and write keys, for use and storage
// by account servers.
const invitation = {
  title: 'invitation',
  type: 'object',
  properties: {
    replicationKey: base64String(crypto.replicationKeyBytes),
    publicKey: base64String(crypto.publicKeyBytes),
    // optional
    secretKey: strictObjectSchema({
      ciphertext: base64String(
        crypto.secretKeyBytes +
        crypto.encryptionMACBytes
      ),
      nonce
    }),
    // optional:
    encryptionKey: strictObjectSchema({
      ciphertext: base64String(
        crypto.encryptionKeyBytes +
        crypto.encryptionMACBytes
      ),
      nonce
    }),
    // optional:
    title: strictObjectSchema({
      ciphertext: base64String(),
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
