const AJV = require('ajv')
const crypto = require('@proseline/crypto')
const tape = require('tape')
const schemas = require('./')

const ajv = new AJV()

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
  const invitationEncryptionKey = crypto.random(crypto.encryptionKeyBytes)

  const replicationKey = crypto.replicationKey()

  const projectEncryptionKey = crypto.encryptionKey()
  const projectEncryptionKeyNonce = crypto.nonce()

  const keyPair = crypto.keyPair()
  const publicKey = keyPair.publicKey
  const secretKey = keyPair.secretKey
  const secretKeyNonce = crypto.nonce()

  const title = 'test project'
  const titleNonce = crypto.nonce()

  const invitation = {
    replicationKey,
    publicKey,
    encryptionKey: {
      ciphertext: crypto.encryptBinary(
        projectEncryptionKey,
        projectEncryptionKeyNonce,
        invitationEncryptionKey
      ),
      nonce: projectEncryptionKeyNonce
    },
    secretKey: {
      ciphertext: crypto.encryptBinary(
        secretKey, secretKeyNonce, invitationEncryptionKey
      ),
      nonce: secretKeyNonce
    },
    title: {
      ciphertext: crypto.encryptString(
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
  const replicationKey = crypto.replicationKey()
  const discoveryKey = crypto.discoveryKey(replicationKey)
  const index = 1
  const prior = crypto.hash(crypto.random(64))
  const entry = {
    discoveryKey,
    index,
    prior,
    type: 'intro',
    name: 'Kyle E. Mitchell',
    device: 'laptop',
    email: 'kyle@example.com',
    phone: '+15551234567',
    timestamp: new Date().toISOString()
  }
  ajv.validate(schemas.entry, entry)
  test.deepEqual(ajv.errors, null, 'valid entry')

  const logKeyPair = crypto.keyPair()
  const projectKeyPair = crypto.keyPair()
  const readKey = crypto.encryptionKey()
  const logPublicKey = logKeyPair.publicKey
  const nonce = crypto.nonce()
  const envelope = {
    discoveryKey,
    logPublicKey,
    index,
    prior,
    logSignature: crypto.signJSON(entry, logKeyPair.secretKey),
    projectSignature: crypto.signJSON(entry, projectKeyPair.secretKey),
    entry: {
      ciphertext: crypto.encryptJSON(entry, nonce, readKey),
      nonce
    }
  }
  ajv.validate(schemas.envelope, envelope)
  test.deepEqual(ajv.errors, null, 'valid envelope')
  test.end()
})
