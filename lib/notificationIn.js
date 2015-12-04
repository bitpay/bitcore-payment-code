'use strict';

var bitcore = require('bitcore-lib');
var _ = bitcore.deps._;
var $ = bitcore.util.preconditions;
var Transaction = bitcore.Transaction;
var BufferUtil = bitcore.util.buffer;
var PublicKey = bitcore.PublicKey;
var PrivateKey = bitcore.PrivateKey;
var Point = bitcore.crypto.Point;
var Secret = require ('./secret')
var BlindingFactor = require ('./blindingFactor')

function NotificationIn() {
};

NotificationIn.fromTransaction = function(tx) {
  var tx = new Transaction(tx);
  var outpoint, pubKey;

  // Get public key
  _.each(tx.inputs, function(i, j) {
    if (!i.script) return;
    if (!i.script.isPublicKeyHashIn()) return;

    pubKey = new PublicKey(i.script.chunks[1].buf);
    outpoint = j;
  });

  if (!pubKey)
    throw new Error('No pubkey found in tx\'s inputs');

  var data;
  // Get op_ret 
  _.each(tx.outputs, function(o, j) {
    if (!o.script) return;

    if (!o.script.isDataOut()) return;
    if (!data)
      data = o.script.getData();
  });

  if (!data)
    throw new Error('No OP_RETURN data found in tx\'s outputs');

  var n= new NotificationIn();
  n.encryptedData = data;
  n.publicKey = pubKey;
  n.outpoint = outpoint;

  return n;
};


NotificationIn.prototype.decrypt = function(secret) {
  if (this.data) return;

  var buf = new Buffer(this.encryptedData);
  var blindingFactor = new BlindingFactor(secret, this.outpoint);
  blindingFactor.apply(buf);
  this.data = buf;

  return buf;
};




module.exports = NotificationIn;
