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
  var encryptionKey = crypto.randomBuffer(crypto.projectReadKeyBytes)

  var replicationKey = crypto.makeProjectReplicationKey()
  var replicationKeyNonce = crypto.randomNonce()

  var readKey = crypto.makeProjectReadKey()
  var readKeyNonce = crypto.randomNonce()

  var writeSeed = crypto.makeSigningKeyPairSeed()
  var writeSeedNonce = crypto.randomNonce()

  var title = 'test project'
  var titleNonce = crypto.randomNonce()

  var invitation = {
    replicationKeyCiphertext: crypto.encrypt(
      replicationKey, replicationKeyNonce, encryptionKey
    ).toString('hex'),
    replicationKeyNonce: replicationKeyNonce.toString('hex'),

    readKeyCiphertext: crypto.encrypt(
      readKey, readKeyNonce, encryptionKey
    ).toString('hex'),
    readKeyNonce: readKeyNonce.toString('hex'),

    writeSeedCiphertext: crypto.encrypt(
      writeSeed, writeSeedNonce, encryptionKey
    ).toString('hex'),
    writeSeedNonce: writeSeedNonce.toString('hex'),

    titleCiphertext: crypto.encrypt(
      Buffer.from(title), titleNonce, encryptionKey
    ).toString('hex'),
    titleNonce: titleNonce.toString('hex')
  }

  test.assert(
    ajv.validate(schemas.invitation, invitation),
    'invalid invitation'
  )
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
      crypto.randomBuffer(64)
    ).toString('hex') // optional
  }
  var logKeyPair = crypto.makeSigningKeyPair()
  var writeKeyPair = crypto.makeSigningKeyPair()
  var clientKeyPair = crypto.makeSigningKeyPair()
  crypto.sign(innerEnvelope, logKeyPair.secretKey, 'logSignature')
  crypto.sign(innerEnvelope, clientKeyPair.secretKey, 'clientSignature') // optional
  crypto.sign(innerEnvelope, writeKeyPair.secretKey, 'projectSignature')
  ajv.validate(schemas.innerEnvelope, innerEnvelope)
  test.deepEqual(ajv.errors, null, 'valid inner envelope')

  var nonce = crypto.randomNonce()
  var replicationKey = crypto.makeProjectReplicationKey()
  var discoveryKey = crypto.makeDiscoveryKey(replicationKey)
  var readKey = crypto.makeProjectReadKey()
  var outerEnvelope = {
    project: discoveryKey.toString('hex'),
    publicKey: logKeyPair.publicKey.toString('hex'),
    index: 1,
    nonce: nonce.toString('hex'),
    encryptedInnerEnvelope: crypto.encrypt(
      Buffer.from(stringify(innerEnvelope)), nonce, readKey
    ).toString('base64')
  }
  ajv.validate(schemas.outerEnvelope, outerEnvelope)
  test.deepEqual(ajv.errors, null, 'valid outer envelope')

  test.end()
})
