'use strict';

var bitcore = require('bitcore-lib');
var _ = bitcore.deps._;
var $ = bitcore.util.preconditions;
var Hash = bitcore.crypto.Hash;
var BN = bitcore.crypto.BN;
var Point = bitcore.crypto.Point;
var PrivateKey = bitcore.PrivateKey;
var PublicKey = bitcore.PublicKey;
var HDPrivateKey = bitcore.HDPrivateKey;

function Secret(x) {
  if (x instanceof Point) {
    x = x.x.toBuffer();
  } else if (!Buffer.isBuffer(x)) {
    x = new Buffer(x,'hex');
  }

  this.x = x;
  this.s = BN.fromBuffer(Hash.sha256(this.x));

  // Validate point, will throw otherwise
  Point.fromX(0, this.s).validate();
};


// private key should be m/47'/0'/0'/0 (notification private key)
Secret.fromNotification = function(notification, privateKey) {
  $.checkArgument(notification, "notificaion key must be supplied");
  $.checkArgument(privateKey, "privateKey key must be supplied");

  if (privateKey instanceof PrivateKey) {
    privateKey = new PrivateKey(privateKey);
  } else {
    var x = bitcore.HDPrivateKey(privateKey);
    privateKey = x.derive('m/0').privateKey;
  }


  var b = privateKey.bn;
  var A = notification.publicKey.point;
  var S = A.mul(b);

  return new Secret(S);
};

Secret.prototype.offsetPublicKey = function(B) {
  if (B instanceof PublicKey) {
    B = B.point;
  }

  var G = Point.getG();

  // payment address:
  var offset = G.mul(this.s);
  B.add(offset);
  return new PublicKey(B);
}; 


Secret.prototype.offsetPrivateKey = function(privKey) {
  $.checkArgument(privKey instanceof PrivateKey);

  var p = privKey.bn;
  var network = privKey.network.name;
console.log('[secret.js.67:network:]',network); //TODO
console.log('[secret.js.67:67:]',privKey.bn); //TODO
console.log('[secret.js.67:67:]',this.s); //TODO

  var privKeyP = p.add(this.s);
  var json =  { 
    bn: privKeyP,
    network: network,
  };
console.log('[secret.js.69:privKeyP:]',json); //TODO
  return new PrivateKey(json);
};


Secret.prototype.computePrivateKey = function(xPrivKey, index) {
  var b = xPrivKey.derive('m/' + index).privateKey;
  return this.offsetPrivateKey(b);
};


Secret.fromString = function(x) {
  return new Secret(x);
};

Secret.prototype.toString = function() {
  return this.x.toString('hex');
};

module.exports  = Secret;
