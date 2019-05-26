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
      'valid schema'
    )
    test.end()
  })
})

tape('invitation', function (test) {
  var encryptionKey = crypto.random(crypto.projectReadKeyBytes)

  var replicationKey = crypto.projectReplicationKey()

  var readKey = crypto.projectReadKey()
  var readKeyNonce = crypto.randomNonce()

  var writeSeed = crypto.signingKeyPairSeed()
  var writeSeedNonce = crypto.randomNonce()

  var title = 'test project'
  var titleNonce = crypto.randomNonce()

  var invitation = {
    replicationKey: replicationKey,

    readKeyCiphertext: crypto.encryptHex(
      readKey, readKeyNonce, encryptionKey
    ),
    readKeyNonce: readKeyNonce,

    writeSeedCiphertext: crypto.encryptHex(
      writeSeed, writeSeedNonce, encryptionKey
    ),
    writeSeedNonce: writeSeedNonce,

    titleCiphertext: crypto.encryptHex(
      title, titleNonce, encryptionKey
    ),
    titleNonce: titleNonce
  }

  ajv.validate(schemas.invitation, invitation)
  test.deepEqual(ajv.errors, null, 'invalid invitation')
  test.end()
})

tape('intro in inner and outer envelopes', function (test) {
  var intro = {
    type: 'intro',
    name: 'Kyle E. Mitchell',
    device: 'laptop',
    timestamp: new Date().toISOString()
  }

  var innerEnvelope = {
    entry: intro,
    prior: crypto.hash(
      crypto.random(64)
    )
  }
  var logKeyPair = crypto.signingKeyPair()
  var writeKeyPair = crypto.signingKeyPair()
  var clientKeyPair = crypto.signingKeyPair()
  crypto.sign(innerEnvelope, logKeyPair.secretKey, 'logSignature')
  crypto.sign(innerEnvelope, clientKeyPair.secretKey, 'clientSignature') // optional
  crypto.sign(innerEnvelope, writeKeyPair.secretKey, 'projectSignature')
  ajv.validate(schemas.innerEnvelope, innerEnvelope)
  test.deepEqual(ajv.errors, null, 'valid inner envelope')

  var nonce = crypto.randomNonce()
  var replicationKey = crypto.projectReplicationKey()
  var projectDiscoveryKey = crypto.discoveryKey(replicationKey)
  var readKey = crypto.projectReadKey()
  var outerEnvelope = {
    projectDiscoveryKey: projectDiscoveryKey,
    logPublicKey: logKeyPair.publicKey,
    index: 1,
    nonce: nonce,
    encryptedInnerEnvelope: crypto.encryptUTF8(
      stringify(innerEnvelope), nonce, readKey
    )
  }
  ajv.validate(schemas.outerEnvelope, outerEnvelope)
  test.deepEqual(ajv.errors, null, 'valid outer envelope')

  test.end()
})
