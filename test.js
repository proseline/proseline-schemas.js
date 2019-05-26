var AJV = require('ajv')
var crypto = require('@proseline/crypto')
var tape = require('tape')
var schemas = require('./')
var stringify = require('fast-json-stable-stringify')

var ajv = new AJV()

// Validate top-level schemas.
Object.keys(schemas).forEach(function (key) {
  tape(key + ' schema', function (test) {
    test.assert(
      ajv.validateSchema(schemas[key]),
      key + ' is valid schema'
    )
    test.end()
  })
})

tape('invitation', function (test) {
  var invitationEncryptionKey = crypto.random(crypto.projectReadKeyBytes)

  var replicationKey = crypto.projectReplicationKey()

  var projectEncryptionKey = crypto.projectReadKey()
  var projectEncryptionKeyNonce = crypto.randomNonce()

  var keyPair = crypto.signingKeyPair()
  var publicKey = keyPair.publicKey
  var secretKey = keyPair.secretKey
  var secretKeyNonce = crypto.randomNonce()

  var title = 'test project'
  var titleNonce = crypto.randomNonce()

  var invitation = {
    replicationKey,
    publicKey,
    encryptionKey: {
      ciphertext: crypto.encryptHex(
        projectEncryptionKey,
        projectEncryptionKeyNonce,
        invitationEncryptionKey
      ),
      nonce: projectEncryptionKeyNonce
    },
    secretKey: {
      ciphertext: crypto.encryptHex(
        secretKey, secretKeyNonce, invitationEncryptionKey
      ),
      nonce: secretKeyNonce
    },
    title: {
      ciphertext: crypto.encryptHex(
        title, titleNonce, invitationEncryptionKey
      ),
      nonce: titleNonce
    }
  }

  ajv.validate(schemas.invitation, invitation)
  test.deepEqual(ajv.errors, null, 'invalid invitation')
  test.end()
})

tape('intro in envelope', function (test) {
  var index = 1
  var prior = crypto.hash(crypto.random(64))
  var entry = {
    index,
    prior,
    type: 'intro',
    name: 'Kyle E. Mitchell',
    device: 'laptop',
    timestamp: new Date().toISOString()
  }
  ajv.validate(schemas.entry, entry)
  test.deepEqual(ajv.errors, null, 'valid entry')

  var replicationKey = crypto.projectReplicationKey()
  var logKeyPair = crypto.signingKeyPair()
  var projectKeyPair = crypto.signingKeyPair()
  var discoveryKey = crypto.discoveryKey(replicationKey)
  var readKey = crypto.projectReadKey()
  var logPublicKey = logKeyPair.publicKey
  var nonce = crypto.randomNonce()
  var stringified = stringify(entry)
  var envelope = {
    discoveryKey,
    logPublicKey,
    index,
    nonce,
    entry,
    encryptedEntry: crypto.encryptUTF8(stringified, nonce, readKey)
  }
  crypto.sign(envelope, logKeyPair.secretKey, 'logSignature')
  crypto.sign(envelope, projectKeyPair.secretKey, 'projectSignature')
  delete envelope.entry
  ajv.validate(schemas.envelope, envelope)
  test.deepEqual(ajv.errors, null, 'valid envelope')

  test.end()
})
