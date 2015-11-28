'use strict';

var bitcore = require('bitcore-lib');
var _ = bitcore.deps._;
var $ = bitcore.util.preconditions;
var BufferUtil = bitcore.util.buffer;
var Hash = bitcore.crypto.Hash;
var Point = bitcore.crypto.Point;

var Address = bitcore.Address;
var PublicKey = bitcore.PublicKey;
var HDPublicKey = bitcore.HDPublicKey;
var HDPrivateKey = bitcore.HDPrivateKey;
var Base58Check = bitcore.encoding.Base58Check;

// From https://github.com/czzarr/node-bitwise-xor/blob/master/index.js
function xor(a, b) {
  if (!Buffer.isBuffer(a)) a = new Buffer(a)
  if (!Buffer.isBuffer(b)) b = new Buffer(b)
  var res = []
  if (a.length > b.length) {
    for (var i = 0; i < b.length; i++) {
      res.push(a[i] ^ b[i])
    }
  } else {
    for (var i = 0; i < a.length; i++) {
      res.push(a[i] ^ b[i])
    }
  }
  return new Buffer(res);
};

function PaymentCode(x) {
  $.checkArgument(x, 'First argument is required, please include extended public key data.');

  var self = this;


  if (x instanceof PaymentCode)
    return x;
  else if (x instanceof HDPublicKey)
    return new PaymentCode([x]);
  else if (_.isArray(x))
    this._buildFromExtendedPublicKeys(x);
  else
    this._buildFromCode(x);

  this._expand();
};



PaymentCode.VERSION = 0x47;


PaymentCode.prototype._buildFromCode = function(x) {
  var data = Base58Check.decode(x);
  var version = data.slice(0, 1);
  $.checkArgument(version[0] == 0x47, "Invalid payment encoding version");

  var buf = this.buffer = data.slice(1);
  $.checkArgument(buf.length % 80 == 0, "Invalid payment code size");

  this.xPubKeys = [];

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
    };

    this.xPubKeys.push(new HDPublicKey(o));
    i += 80;
  };
};


PaymentCode.prototype._getEncrypted = function(bf) {
  return this._calcBuffer(bf);
};

// Will throw is point is not valid, so client can increment index
PaymentCode.prototype.makePaymentInfo = function(hisPc, xPrivKey, index, outpoint) {
  $.checkArgument(xPrivKey, "Privakey key must be supplied");
  $.checkArgument(_.isNumber(index), "Index must be a number");
  $.checkArgument(_.isNumber(outpoint), "Outpoint must be a number");

  var self = this;
  var ownHDPrivKey = HDPrivateKey(xPrivKey);
  var ownHDPubKey = HDPrivateKey(xPrivKey).hdPublicKey;

  $.checkArgument(_.any(this.xPubKeys, function(x) {
    return x = ownHDPubKey
  }), 'The supplied private key does not match the payment code\'s public keys');

  var publicKeys = [];
  var secrets = [];
  var notificationOutputs = [];

  var G = Point.getG();

  var privateKey = ownHDPrivKey.derive('m/0').privateKey;
  var a = privateKey.bn;

  var hisPC = new PaymentCode(hisPc);
  var path = 'm/' + index;
  _.each(hisPC.xPubKeys, function(xpub) {
    var pubKey = xpub.derive(path).publicKey;
    var B = pubKey.point;

    var S = B.mul(a);
    var Sx = new Buffer(S.x, 'hex');
    var s = Hash.sha256(Sx);

    // Validate point, will throw otherwise
    var p = Point.fromX(0, s);

    // payment address:
    var offset = G.mul(s);
    var Bp = B.add(offset);

    // blinding factor
    var bf = Hash.sha512hmac(Sx, BufferUtil.integerAsBuffer(outpoint));
    var output = self._getEncrypted(bf);
    publicKeys.push(new PublicKey(Bp));
    secrets.push(s.toString('hex'));
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

  if (!this.buffer)
    this.buffer = this._calcBuffer();
};

PaymentCode.prototype._calcBuffer = function(blidingFactor) {

  if (blidingFactor)
    $.checkArgument(blidingFactor.length == 64, 'Bliding factor should have 64 bytes');

  $.checkState(this.xPubKeys.length == 1, "Multisig Payment Codes not supported yet")

  var reserved = new Buffer(13);
  reserved.fill(0);
  var pcs = _.map(this.xPubKeys, function(x) {
    var obj = x.toObject();
    var pub = new Buffer(obj.publicKey, 'hex');
    var chain = new Buffer(obj.chainCode, 'hex');

    if (blidingFactor) {
      var pubBf = blidingFactor.slice(0, 32);
      pubBf = Buffer.concat([new Buffer('00', 'hex'), pubBf]);
      pub = xor(pub, pubBf);
      chain = xor(chain, blidingFactor.slice(32, 64));
    };

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
  return Base58Check.encode(this.toBuffer());
};

module.exports = PaymentCode;
