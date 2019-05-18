var AJV = require('ajv')
var tape = require('tape')
var schemas = require('./')
var sodium = require('sodium-universal')
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
  var encryptionKey = makeStreamEncryptionKey()

  var replicationKey = makeStreamEncryptionKey()
  var replicationKeyNonce = randomNonce()

  var readKey = makeBoxEncryptionKey()
  var readKeyNonce = randomNonce()

  var writeSeed = makeSeed()
  var writeSeedNonce = randomNonce()

  var title = 'test project'
  var titleNonce = randomNonce()

  var invitation = {
    replicationKeyCiphertext: encrypt(
      replicationKey, replicationKeyNonce, encryptionKey
    ).toString('hex'),
    replicationKeyNonce: replicationKeyNonce.toString('hex'),

    readKeyCiphertext: encrypt(
      readKey, readKeyNonce, encryptionKey
    ).toString('hex'),
    readKeyNonce: readKeyNonce.toString('hex'),

    writeSeedCiphertext: encrypt(
      writeSeed, writeSeedNonce, encryptionKey
    ).toString('hex'),
    writeSeedNonce: writeSeedNonce.toString('hex'),

    titleCiphertext: encrypt(
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
    message: intro,
    prior: hash(randomBuffer(64)).toString('hex') // optional
  }
  var logKeyPair = makeKeyPair()
  var writeKeyPair = makeKeyPair()
  var clientKeyPair = makeKeyPair()
  sign(innerEnvelope, logKeyPair, 'logSignature')
  sign(innerEnvelope, clientKeyPair, 'clientSignature') // optional
  sign(innerEnvelope, writeKeyPair, 'projectSignature')
  ajv.validate(schemas.innerEnvelope, innerEnvelope)
  test.deepEqual(ajv.errors, null, 'valid inner envelope')

  var nonce = randomNonce()
  var replicationKey = makeStreamEncryptionKey()
  var discoveryKey = makeDiscoveryKey(replicationKey)
  var readKey = makeBoxEncryptionKey()
  var outerEnvelope = {
    project: discoveryKey.toString('hex'),
    publicKey: logKeyPair.publicKey.toString('hex'),
    index: 1,
    nonce: nonce.toString('hex'),
    encryptedInnerEnvelope: encrypt(
      Buffer.from(stringify(innerEnvelope)), nonce, readKey
    ).toString('base64')
  }
  ajv.validate(schemas.outerEnvelope, outerEnvelope)
  test.deepEqual(ajv.errors, null, 'valid outer envelope')

  test.end()
})

// Helper Functions

function makeSeed () {
  var seed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
  sodium.randombytes_buf(seed)
  return seed
}

function randomBuffer (bytes) {
  var buffer = Buffer.alloc(bytes)
  sodium.randombytes_buf(buffer)
  return buffer
}

function randomNonce () {
  return randomBuffer(sodium.crypto_secretbox_NONCEBYTES)
}

function makeStreamEncryptionKey () {
  var key = Buffer.alloc(sodium.crypto_stream_KEYBYTES)
  sodium.randombytes_buf(key)
  return key
}

function makeBoxEncryptionKey () {
  var key = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)
  sodium.randombytes_buf(key)
  return key
}

function encrypt (plaintext, nonce, key) {
  var ciphertext = Buffer.alloc(
    plaintext.length + sodium.crypto_secretbox_MACBYTES
  )
  sodium.crypto_secretbox_easy(ciphertext, plaintext, nonce, key)
  return ciphertext
}

function makeKeyPair () {
  var publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  var secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey: publicKey, secretKey: secretKey }
}

function makeDiscoveryKey (encryptionKey) {
  var discoveryKey = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash(discoveryKey, encryptionKey)
  return discoveryKey
}

function sign (object, keyPair, key) {
  var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(
    signature,
    Buffer.from(stringify(object.message), 'utf8'),
    keyPair.secretKey
  )
  object[key] = signature.toString('hex')
}

function hash (input) {
  var digest = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash(digest, input)
  return digest
}
