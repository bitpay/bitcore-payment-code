'use strict';

var xor = require('./xor');
var bitcore = require('bitcore-lib');
var _ = bitcore.deps._;
var $ = bitcore.util.preconditions;
var Hash = bitcore.crypto.Hash;
var BufferUtil = bitcore.util.buffer;
var BN = bitcore.crypto.BN;
var Point = bitcore.crypto.Point;

function BlindingFactor(secret, outpoint) {
  $.checkArgument(_.isNumber(outpoint), "Outpoint must be a number");
  this.buffer = Hash.sha512hmac(secret.x, BufferUtil.integerAsBuffer(outpoint));
  
  var pubBf =this.buffer.slice(0, 32);
  this.publicKeyFactor = Buffer.concat([new Buffer('00', 'hex'), pubBf]);
  this.chainCodeFactor = this.buffer.slice(32, 64);
};


BlindingFactor.prototype.apply = function(buf) {
  $.checkArgument(buf.length % 80 == 0, "Invalid buf size");

  var i = 0;
  while (i < buf.length) {
    var publicKey =  buf.slice(i + 2, i + 2 + 33);
    var chainCode = buf.slice(i + 35, i + 35 + 32);
    publicKey = xor(publicKey, this.publicKeyFactor);
    chainCode = xor(chainCode, this.chainCodeFactor);

    // update buffer
    publicKey.copy(buf, i + 2, 0, 33);
    chainCode.copy(buf, i + 35, 0, 32);
    i+=80;
  };
};

BlindingFactor.prototype.toString = function() {
  return this.buffer.toString('hex');
};

module.exports  = BlindingFactor;
