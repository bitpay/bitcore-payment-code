'use strict';

var xor = require('./xor');
var bitcore = require('bitcore-lib');
var _ = bitcore.deps._;
var $ = bitcore.util.preconditions;
var BufferUtil = bitcore.util.buffer;
var Hash = bitcore.crypto.Hash;
var Point = bitcore.crypto.Point;
var BN = bitcore.crypto.BN;

var Address = bitcore.Address;
var PrivateKey = bitcore.PrivateKey;
var PublicKey = bitcore.PublicKey;
var HDPublicKey = bitcore.HDPublicKey;
var HDPrivateKey = bitcore.HDPrivateKey;
var Base58Check = bitcore.encoding.Base58Check;

var Secret =  require('./secret');
var BlindingFactor =  require('./blindingFactor');
var NotificationOut =  require('./notificationOut');

// If xpriv / xpub is supplied, it must be previosly derived to, eg, m/47'/0'/0'
function PaymentCode(x,  network) {
  $.checkArgument(x, 'First argument is required');

  var self = this;


  if (x instanceof PaymentCode)
    return x;
  else if (x instanceof HDPrivateKey)
    return new PaymentCode([x.hdPublicKey]);
  else if (x instanceof HDPublicKey)
    return new PaymentCode([x]);
  else if (_.isArray(x))
    this._buildFromExtendedPublicKeys(x);
  else if (Buffer.isBuffer(x))
    this._buildFromBuffer(x, network);
  else
    this._buildFromCode(x);

  this._expand();
};

PaymentCode.VERSION = 0x47;

PaymentCode.prototype._buildFromBuffer = function(data,  network) {
  var buf = this.buffer = data;
  $.checkArgument(buf.length % 80 == 0, "Invalid payment code size");

  this.xPubKeys = [];
  network = network || 'livenet';

  var i = 0;
  while (i < buf.length) {
    var version = buf.slice(i, 1);
    $.checkArgument(version[0] == 1, "Only payment codes version 1 are supported");

    var o = {
      version: BufferUtil.integerAsBuffer(0),
      depth: BufferUtil.integerAsSingleByteBuffer(0),
      parentFingerPrint: (new Buffer(4)).fill(0),
      childIndex: BufferUtil.integerAsBuffer(0),
      publicKey: buf.slice(i + 2, i + 2 + 33),
      chainCode: buf.slice(i + 35, i + 35 + 32),
      network: network,
    };

    this.xPubKeys.push(new HDPublicKey(o));
    i += 80;
  };
};


PaymentCode.prototype._buildFromCode = function(x) {
  var data = Base58Check.decode(x);
  var version = data.slice(0, 1);
  $.checkArgument(version[0] == 0x47, "Invalid payment encoding version");

  // TODO network (version[0] == xx
  var network = 'livenet';

  return this._buildFromBuffer(data.slice(1), network);
};

PaymentCode.prototype.buildNotificationTo = function(hisPc, privateKey, outpoint) {
  return new NotificationOut(this.toString(), hisPc, privateKey, outpoint);
};

// Will throw if resulting point is not valid, so client can increment index
PaymentCode.prototype.makePaymentInfo = function(hisPc, xPrivKey, index, outpoint) {
  $.checkArgument(xPrivKey, "Privakey key must be supplied");
  $.checkArgument(_.isNumber(index), "Index must be a number");
  $.checkArgument(_.isNumber(outpoint), "Outpoint must be a number");

  var self = this;
  var ownHDPrivKey = HDPrivateKey(xPrivKey);
  var ownHDPubKey = ownHDPrivKey.hdPublicKey;

  $.checkArgument(_.any(this.xPubKeys, function(x) {
    return x = ownHDPubKey
  }), 'The supplied private key does not match the payment code\'s public keys');

  var n = new NotificationOut(this, hisPc, p);

  var publicKeys = [];
  var secrets = [];
  var notificationOutputs = [];


  var privateKey = ownHDPrivKey.derive('m/0').privateKey;
  var a = privateKey.bn;

  hisPc = new PaymentCode(hisPc);
  var path = 'm/' + index;

  _.each(hisPc.xPubKeys, function(xpub) {
    var pubKey = xpub.derive(path).publicKey;
    var B = pubKey.point;

    var secret = new Secret(B.mul(a));
    var Bp = secret.offsetPublicKey(B);

    // blinding factor
    var bf = new BlindingFactor(secret, outpoint);

console.log('##IN :', self.buffer.toString('hex')); //TODO
    var output = new Buffer(self.buffer);
    bf.apply(output);
console.log('##OUT:',output.toString('hex')); //TODO

    publicKeys.push(new PublicKey(Bp));
    secrets.push(secret.toString());
    notificationOutputs.push(output.toString('hex'));
  });

  var payAddress;
  if (publicKeys.length == 1) {
    payAddress = publicKeys[0].toAddress().toString();
  }

  return {
    publicKeys: _.map(publicKeys, function(x) {
      return x.toString();
    }),
    paymentAddress: payAddress,
    secrets: secrets,
    notificationOutputs: notificationOutputs,
    notificationAddresses: hisPc.notificationAddresses,
  };
};


PaymentCode.prototype.computePaymentPublicKeys = function(secret, index) {
  var res = [];

  _.each(this.xPubKeys, function(x) {
    var B = x.derive('m/' + index).publicKey.point;

    // payment address:
    var offset = G.mul(secret);
    var Bp = B.add(offset);

    res.push(new PublicKey(Bp));

  });

  return res;
};

PaymentCode.prototype.computePaymentAddress = function(secret, index) {
  $.checkState(this.n == 1, 'No payment address associated to multisig payment codes');

  var B = this.xPubKeys[0].derive('m/' + index).publicKey.point;

  // payment address:
  var offset = G.mul(secret);
  var Bp = B.add(offset);

  var publicKey = new PublicKey(Bp);
  return publicKey.toAddress();
};

PaymentCode.prototype.computePaymentPrivateKey = function(xPrivKey, secret, index) {
  var b = xPrivKey.derive('m/' + index).privateKey.bn;
  var bp = b.add(s);

  // Check all is OK (slow)
  //$.checkState(Bp.eq(G.mul(bp)), 'Could not find private key for ephemeral address');

  return PrivateKey.fromBuffer(bp.toBuffer());
};

PaymentCode.prototype._buildFromExtendedPublicKeys = function(xPubKeys) {
  var self = this;
  this.network = xPubKeys[0].network.name;

  this.xPubKeys = _.map(xPubKeys, function(x) {
    var x = new HDPublicKey(x);
    $.checkState(x.network.name == self.network, 'Public Keys from different network provided');
    return x;
  });
};


PaymentCode.prototype._expand = function() {
  var self = this;

  this.notificationPublicKeys = _.map(this.xPubKeys, function(x) {
    return x.derive('m/0').publicKey;
  });


  this.notificationAddresses = _.map(this.notificationPublicKeys, function(x) {
    return new Address.fromPublicKey(new PublicKey(x), self.network).toString();
  });

  this.n = this.xPubKeys.length;

  if (!this.buffer) {
    this.buffer = this._calcBuffer();
  }
};

PaymentCode.prototype._calcBuffer = function() {
  $.checkState(this.xPubKeys.length == 1, "Multisig Payment Codes not supported yet")

  var reserved = new Buffer(13);
  reserved.fill(0);
  var pcs = _.map(this.xPubKeys, function(x) {
    var obj = x.toObject();
    var pub = new Buffer(obj.publicKey, 'hex');
    var chain = new Buffer(obj.chainCode, 'hex');

    var pc = new Buffer('0100', 'hex'); // version + options
    pc = Buffer.concat([pc, pub]);
    pc = Buffer.concat([pc, chain]);
    $.checkState(pc.length == 67, 'Missing or wrong publicKey or chainCode');
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
  var str = Base58Check.encode(this.toBuffer());
  return str;
};

module.exports = PaymentCode;
