'use strict';

var bitcore = require('bitcore-lib');
var _ = bitcore.deps._;
var $ = bitcore.util.preconditions;
var Hash = bitcore.crypto.Hash;
var BN = bitcore.crypto.BN;
var Point = bitcore.crypto.Point;
var PrivateKey = bitcore.PrivateKey;

function Secret(point) {
  $.checkArgument(point instanceof Point, 'Must initialize with Point');

  this.x = point.x.toBuffer();
  this.s = BN.fromBuffer(Hash.sha256(this.x));

  // Validate point, will throw otherwise
  Point.fromX(0, this.s);
};


// private key should be m/47'/0'/0'/0 (notification private key)
Secret.fromNotification = function(notification, privateKey) {
  $.checkArgument(notification, "notificaion key must be supplied");
  $.checkArgument(privateKey, "privateKey key must be supplied");

  privateKey = new PrivateKey(privateKey);

  var b = privateKey.bn;
  var A = notification.publicKey.point;
  var S = A.mul(b);

  return new Secret(S);
};

Secret.prototype.offsetPublicKey = function(B) {
  var G = Point.getG();

  // payment address:
  var offset = G.mul(this.s);
  B.add(offset);
  return B;
}; 


Secret.prototype.toString = function() {
  return this.s.toString('hex');
};

module.exports  = Secret;
