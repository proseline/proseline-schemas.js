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
  var encryptionKey = crypto.random(crypto.projectReadKeyBytes)

  var replicationKey = crypto.projectReplicationKey()

  var readKey = crypto.projectReadKey()
  var readKeyNonce = crypto.randomNonce()

  var projectKeyPair = crypto.signingKeyPair()
  var projectPublicKey = projectKeyPair.publicKey
  var projectSecretKey = projectKeyPair.secretKey
  var projectSecretKeyNonce = crypto.randomNonce()

  var title = 'test project'
  var titleNonce = crypto.randomNonce()

  var invitation = {
    replicationKey,
    projectPublicKey,

    readKeyCiphertext: crypto.encryptHex(
      readKey, readKeyNonce, encryptionKey
    ),
    readKeyNonce,

    projectSecretKeyCiphertext: crypto.encryptHex(
      projectSecretKey, projectSecretKeyNonce, encryptionKey
    ),
    projectSecretKeyNonce,

    titleCiphertext: crypto.encryptHex(
      title, titleNonce, encryptionKey
    ),
    titleNonce
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
