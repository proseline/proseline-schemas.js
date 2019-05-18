var AJV = require('ajv')
var assert = require('assert')
var schemas = require('./')
var sodium = require('sodium-universal')

var ajv = new AJV()

// Validate message schemas.
/*
var messages = schemas.messages
Object.keys(messages).forEach(function (key) {
  assert(
    ajv.validateSchema(messages[key]),
    key + ' message schema invalid'
  )
})
*/

// Validate top-level schemas.
Object.keys(schemas)
  .filter(function (key) { return key !== 'messages' })
  .forEach(function (key) {
    assert(
      ajv.validateSchema(schemas[key]),
      key + ' schema invalid'
    )
  })

// Validate an example invitation.
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

assert(
  ajv.validate(schemas.invitation, invitation),
  'invalid invitation'
)

function makeSeed () {
  var seed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
  sodium.randombytes_buf(seed)
  return seed
}

function randomNonce () {
  var nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)
  return nonce
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
  sodium.crypto_secretbox_easy(
    ciphertext, plaintext, nonce, key
  )
  return ciphertext
}
