'use strict';

var bitcore = require('bitcore-lib');
var _ = bitcore.deps._;
var $ = bitcore.util.preconditions;

var Address = bitcore.Address;
var PublicKey = bitcore.PublicKey;
var Base58Check = bitcore.encoding.Base58Check;

function PaymentCode(xPubKeys) {
  $.checkArgument(xPubKeys, 'First argument is required, please include extended public key data.');

  var self = this;

  if (!_.isArray(xPubKeys))
    return new PaymentCode([xPubKeys]);

  this.network  =xPubKeys[0].network.name;

  this.xPubKeys = _.map(xPubKeys, function(x) {
    var x=  new bitcore.HDPublicKey(x);
    $.checkState(x.network.name == self.network, 'Public Keys from different network provided');
    return x;
  });

  this._expand();
};

PaymentCode.VERSION = 0x47;

PaymentCode.prototype._expand = function() {
  var self = this;

  this.notificationPublicKeys = _.map(this.xPubKeys, function(x) {
    return x.derive('m/0').publicKey;
  });


  this.notificationAddresses = _.map(this.notificationPublicKeys, function(x) {
    return new Address.fromPublicKey(new PublicKey(x), self.network);
  });

  this.n = this.xPubKeys.length;
  this.buffer  = this._calcBuffer();
};

PaymentCode.prototype._calcBuffer = function() {

  $.checkState(this.xPubKeys.length==1,"Multisig Payment Codes not supported yet")

  var reserved = new Buffer(13);
  reserved.fill(0);
  var pcs = _.map(this.xPubKeys, function(x) {
   var obj =  x.toObject();

   var pc = new Buffer('0100', 'hex');      // version + options
   pc = Buffer.concat([pc, new Buffer(obj.publicKey,'hex')]); //
   pc = Buffer.concat([pc, new Buffer(obj.chainCode,'hex')]); //
   $.checkState(pc.length==67, 'Missing or wrong publicKey or chainCode');
   pc = Buffer.concat([pc, reserved]); // reserved bytes
   return pc;
  });

  return pcs[0];
};

/**
 * Will return a buffer representation of the paymentcode 
 *
 * @returns {Buffer} Bitcoin address buffer
 */
PaymentCode.prototype.toBuffer = function() {
  var version = new Buffer([PaymentCode.VERSION]);
  var buf = Buffer.concat([version, this.buffer]);
  return buf;
};

/**
 * Will return a the string representation of the address
 *
 * @returns {string} Bitcoin address
 */
PaymentCode.prototype.toString = function() {
  return Base58Check.encode(this.toBuffer());
};

module.exports = PaymentCode;
