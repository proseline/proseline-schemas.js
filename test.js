var AJV = require('ajv')
var assert = require('assert')
var schemas = require('./')

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
