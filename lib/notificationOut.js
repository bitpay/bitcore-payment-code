'use strict';

var bitcore = require('bitcore-lib');
var _ = bitcore.deps._;
var $ = bitcore.util.preconditions;
var Transaction = bitcore.Transaction;
var BufferUtil = bitcore.util.buffer;
var PublicKey = bitcore.PublicKey;
var PrivateKey = bitcore.PrivateKey;
var Script = bitcore.Script;
var Point = bitcore.crypto.Point;
var Secret = require ('./secret');
var BlindingFactor = require ('./blindingFactor');
var PaymentCode = require('./paymentCode');

function NotificationOut(senderPc, recipientPc, utxoPrivateKey, outpoint) {
  $.checkArgument(utxoPrivateKey, "utxoPrivateKey key must be supplied");
  outpoint  = outpoint || 0;
  var self = this;

  var privateKey = new PrivateKey(utxoPrivateKey);
console.log('[notificationOut.js.22:senderPc:]',senderPc); //TODO
  var ourPc = new PaymentCode(senderPc);
  var hisPc = new PaymentCode(recipientPc);

  var publicKeys = [];
  var secrets = [];
  var outputs = [];

  var a = privateKey.bn;

  _.each(hisPc.xPubKeys, function(xpub) {
    var pubKey =xpub.derive('m/0').publicKey;
    var B = pubKey.point;
    var secret = new Secret(B.mul(a));
    var bf = new BlindingFactor(secret, outpoint);

console.log('##IN :',ourPc.buffer.toString('hex')); //TODO
    var output = new Buffer(ourPc.buffer);
    bf.apply(output);
console.log('[notificationOut.js.38:bf:]',bf.toString()); //TODO
console.log('##OUT:',output.toString('hex')); //TODO
    secrets.push(secret);
    outputs.push(output.toString('hex'));
  });

  this.secrets = secrets;
  this.outputs = outputs
  this.utxoPublicKey = utxoPrivateKey.publicKey;
};

NotificationOut.prototype.getScriptPubKey = function() {
   return Script.buildPublicKeyHashOut(this.utxoPublicKey);
};

module.exports = NotificationOut;
