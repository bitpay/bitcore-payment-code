'use strict';

var chai = require('chai');
var should = chai.should();
var expect = chai.expect;
var bitcore = require('bitcore-lib');
var _ = bitcore.deps._;
var PrivateKey = bitcore.PrivateKey;
var PublicKey = bitcore.PublicKey;
var HDPrivateKey = bitcore.HDPrivateKey;
var Point = bitcore.crypto.Point;

var is_browser = process.browser;

var PC = require('../');
var PaymentCode = PC.PaymentCode;
var NotificationIn = PC.NotificationIn;
var NotificationOut = PC.NotificationOut;
var Secret = PC.Secret;

var x = new bitcore.HDPrivateKey('xprv9s21ZrQH143K2mKd7JFg7TLZaD6kYvuUGCq2RRqBGUxD7r14Acyaizf42LiGpSJxGCd8AKh4KXowS348PuhUxpTx45yw5iUc8ktXrWXLRnR');
var tc1 = {
  xPrivKey: x,
  xPubKey: x.hdPublicKey,
  paymentCode: 'PM8TJgiBF3npDfpxaKqU9W8iDL3T9v8j1RMVqoLqNFQcFdJ6PqjmcosHEQsHMGwe3CcgSdPz46NvJkNpHWym7b3XPF2CMZvcMT5vCvTnh58zpw529bGn',
  notificationPublicKeys: ['03032f6a9fa2e495b056755dfda82b288e22a71851032c02450e6ebbbef1695191'],
  notificationAddresses: ['18VPtWU95XYkKu47nrARz6hpQEzZmBPJMu'],
};

x = new bitcore.HDPrivateKey('xprv9s21ZrQH143K2nvwJx7FDB1qugo9xZxaRqMzsV72RxWaLwsMpmg8GsYsVEiwQD7qSpyuXn8oCUBdFbKnDBBKogtbtzBR2ubz5nPg8ojowWv');
var tc2 = {
  xPrivKey: x,
  xPubKey: x.hdPublicKey,
  paymentCode: 'PM8TJe68G1AE62CVEchCC7HnXnAa4PfxWPtYPsfnZ5ishRvo2qe6H3DcrN94ZU8DZ2CwAFDzqucPzSy9XstwQkfKD1A3VnhUvqUKvk5V9PFar9Ww3dsD',
  notificationAddresses: ['14L2fpcYwQQMmJvVJeewyuvdGfi49HmCZY'],
};

describe('PaymentCode', function() {


  describe('Constructor', function() {

    it('should be able to create class', function() {
      should.exist(PaymentCode);
    });

    it('Should create a code and notification address from given xprivkey', function() {
      var pc = new PaymentCode(tc1.xPubKey);
      pc.toString().should.equal(tc1.paymentCode);

      _.map(pc.notificationPublicKeys, function(x) {
        return x.toString();
      }).should.deep.equal(tc1.notificationPublicKeys);


      _.map(pc.notificationAddresses, function(x) {
        return x.toString();
      }).should.deep.equal(tc1.notificationAddresses);

    });


    it('Should create a code and notification address for testnet', function() {
      var xPrivKey = new bitcore.HDPrivateKey('tprv8ZgxMBicQKsPeLrhpQpsUiPJScGKR9BseEnqAgJt9CigLtmXY3Xv6FpBKwfkQmRDPw52gWEudFRSvLZkRZ6LGg6xMiZYdECDZmV2zqJcAwC');
      var xPubKey = xPrivKey.hdPublicKey;
      var pc = new PaymentCode(xPubKey);
      pc.toString().should.equal('PM8TJgMCSN9tJZYtWNwScstmwtPiRCw5ek8U2xEnJ53Jomji14jitFBEkhDg4SG2Vsj1VfsFbvHHiEa3Asmh4bxNw3kHgsmujPVziR25CUeTpvvH58zu');

      _.map(pc.notificationPublicKeys, function(x) {
        return x.toString();
      }).should.deep.equal(['03f89b439914df5f1a6bf274afa8a4f97a2c1639fcc21658d8f29902f42dc1d2f1']);


      _.map(pc.notificationAddresses, function(x) {
        return x.toString();
      }).should.deep.equal(['mzwzWysDsE8YunuFRgBCAAr2cgh1b81Qap']);

    });

    it('Should create from code', function() {
      var pc = new PaymentCode(tc1.paymentCode);


      _.map(pc.notificationPublicKeys, function(x) {
        return x.toString();
      }).should.deep.equal(tc1.notificationPublicKeys);


      _.map(pc.notificationAddresses, function(x) {
        return x.toString();
      }).should.deep.equal(tc1.notificationAddresses);
    });
  });

  describe('Notifications', function() {
    it('Should create an outgoing notification', function() {
      var p = new PrivateKey('a0b2bd6acc4fecf7d2b77d637f6bd4450e9ca701d5761b29ed824daab9e76361');
      var n = new NotificationOut(tc1.paymentCode, tc2.paymentCode, p);
      n.secrets[0].s.toString().should.equal('111469559018469246850263566406445487050435344289391776306916960726180370386701');
    });

    it('Secret notification roundtrip', function() {

      // ALICE
      var utxoPrivKey = new PrivateKey('a0b2bd6acc4fecf7d2b77d637f6bd4450e9ca701d5761b29ed824daab9e76361');
      var n = new NotificationOut(tc1.paymentCode, tc2.paymentCode, utxoPrivKey);

      var tx = new bitcore.Transaction()
        .from({
          "txid": "3e46af54b2a79e8a343145e91e4801ea8611a69cd29852ff95e4b547cfd90b7b",
          "vout": 0,
          "scriptPubKey": n.getScriptPubKey().toString(),
          "amount": 1
        })
        .addData(n.outputs[0])
        .to(tc2.notificationAddresses[0], 100000)
        .sign(utxoPrivKey);

      // BOB
      var nIn = NotificationIn.fromTransaction(tx.uncheckedSerialize());
      var secret = Secret.fromNotification(nIn, tc2.xPrivKey);

      secret.s.toString('hex').should.equal(n.secrets[0].s.toString('hex'));
      secret.x.toString('hex').should.equal(n.secrets[0].x.toString('hex'));
    });
  });


  describe('Payment Notification from Alice to Bob', function() {
    var a, b;

    beforeEach(function() {
      a = tc1;
      b = tc2;
    });

    it('Should decode a notification tx (Bob receives notification from Alice)', function() {
      var alice = new PaymentCode([a.xPubKey]);
      var utxoPrivKey = new PrivateKey('a0b2bd6acc4fecf7d2b77d637f6bd4450e9ca701d5761b29ed824daab9e76361');
      //var utxoPrivKey = new PrivateKey();
      var fromAliceToBob = alice.buildNotificationTo(b.paymentCode, utxoPrivKey);
      var txToBob = new bitcore.Transaction()
        .from({
          "txid": "3e46af54b2a79e8a343145e91e4801ea8611a69cd29852ff95e4b547cfd90b7b",
          "vout": 0,
          "scriptPubKey": fromAliceToBob.getScriptPubKey().toString(),
          "amount": 1
        })
        .addData(fromAliceToBob.outputs[0])
        .to(b.notificationAddresses[0], 100000);

      var x = bitcore.HDPrivateKey(a.xPrivKey);
      txToBob.sign(utxoPrivKey);
      var txToBobHex = txToBob.uncheckedSerialize();

      // BOB

      var bob = new PaymentCode(b.paymentCode);
      var n = NotificationIn.fromTransaction(txToBob);
      var secret = Secret.fromNotification(n, b.xPrivKey);
      var herPc = new PaymentCode(n.decrypt(secret));

      herPc.toString().should.equal(a.paymentCode);
      herPc.xPubKeys[0].toString().should.equal(a.xPubKey.toString());
    });
  });


  describe('Key Offsetting with Secret', function() {
    var a, b;

    beforeEach(function() {
      a = tc1;
      b = tc2;
    });

    it('Should generate a valid key pair after offsetting', function() {
      var xpriv = HDPrivateKey(a.xPrivKey);

      var randomPrivateKey = new PrivateKey();
      var secret = new Secret(randomPrivateKey.publicKey.point);

      // New pair
      var priv = new PrivateKey();
      var pub = priv.publicKey;

      // Offsetted pair
      var privP = secret.offsetPrivateKey(priv);
      var pubP = secret.offsetPublicKey(pub);

      privP.publicKey.toString().should.equal(pubP.toString());
    });

    it('Should generate a valid key pair after offsetting with paycodes', function() {

      var randomPrivateKey = new PrivateKey();
      var secret = new Secret(randomPrivateKey.publicKey.point);

      var xpriv = HDPrivateKey(a.xPrivKey);
      var xpub = xpriv.hdPublicKey;

      var alice = new PaymentCode(xpub);

      var pubP = alice.computePaymentPublicKeys(secret, 0)[0];
      var privP = secret.computePrivateKey(xpriv, 0);

      privP.publicKey.toString().should.equal(pubP.toString());
    });

  });

  describe('Multiple Payments from Alice to Bob', function() {
    var alice, bob, secret, aXPrivKey;

    before(function() {
      var a = tc1;
      var b = tc2;
      alice = new PaymentCode([a.xPubKey]);
      var utxoPrivKey = new PrivateKey();
      //var utxoPrivKey = new PrivateKey();
      var fromAliceToBob = alice.buildNotificationTo(b.paymentCode, utxoPrivKey);
      var txToBob = new bitcore.Transaction()
        .from({
          "txid": "3e46af54b2a79e8a343145e91e4801ea8611a69cd29852ff95e4b547cfd90b7b",
          "vout": 0,
          "scriptPubKey": fromAliceToBob.getScriptPubKey().toString(),
          "amount": 1
        })
        .addData(fromAliceToBob.outputs[0])
        .to(b.notificationAddresses[0], 100000);

      var x = bitcore.HDPrivateKey(a.xPrivKey);
      txToBob.sign(utxoPrivKey);
      var txToBobHex = txToBob.uncheckedSerialize();

      // BOB

      bob = new PaymentCode(b.paymentCode);
      var n = NotificationIn.fromTransaction(txToBob);
      secret = Secret.fromNotification(n, b.xPrivKey);
      aXPrivKey = new HDPrivateKey(a.xPrivKey);
    });

    var G = Point.getG();
    _.each(_.range(1, 10), function(i) {
      it('Should create valid payment address ' + i + ' (Bob from Alice)', function() {
        // Alice
        var paymentAddress = alice.computePaymentAddress(secret, i);
        var pubKeyP = alice.computePaymentPublicKeys(secret, i)[0];
        pubKeyP.toAddress().toString().should.equal(paymentAddress.toString());
      });

      it('Should create valid payment ' + i + ' (Bob from Alice)', function() {

        var pubKeyP = alice.computePaymentPublicKeys(secret, i)[0];
        var privKeyP = secret.computePrivateKey(aXPrivKey, i);
        privKeyP.publicKey.toString().should.equal(pubKeyP.toString());
      });

    });
  });
});
