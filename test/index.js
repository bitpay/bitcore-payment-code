'use strict';

var chai = require('chai');
var should = chai.should();
var expect = chai.expect;
var bitcore = require('bitcore-lib');
var _ = bitcore.deps._;
var PrivateKey = bitcore.PrivateKey;
var PublicKey = bitcore.PublicKey;

var is_browser = process.browser;

var PaymentCode = require('../');

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

  it('should be able to create class', function() {
    should.exist(PaymentCode);
  });

  describe('Constructor', function() {

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


  describe('Payment from Alice to Bob', function() {
    var a, b;

    beforeEach(function() {
      a = tc1;
      b = tc2;
    });

    it('Should create a notification output (Alice to Bob)', function() {
      var alice = new PaymentCode([a.xPubKey]);
      var fromAliceToBob = alice.makePaymentInfo(b.paymentCode, a.xPrivKey, 1, 0);
      fromAliceToBob.notificationAddresses.should.deep.equal(b.notificationAddresses);
      fromAliceToBob.secrets.should.deep.equal(['1d448afd928065458cf670b60f5a594d735af0172c8d67f22a81680132681ca']);
      fromAliceToBob.paymentAddress.should.equal('1AJ3gNTaJ96NBDcj4cVmPZVBB7sF9rVA31');
    });

    it('Should decode a notification tx (Bob receives notification from Alice)', function() {
      var alice = new PaymentCode([a.xPubKey]);
      var fromAliceToBob = alice.makePaymentInfo(b.paymentCode, a.xPrivKey, 1, 0);

      var txToBob = new bitcore.Transaction()
        .from({
          "txid": "3e46af54b2a79e8a343145e91e4801ea8611a69cd29852ff95e4b547cfd90b7b",
          "vout": 0,
          "scriptPubKey": "76a9145227a227819489ee792a7253d2fe6c764673123288ac",
          "amount": 4.9998
        })
        .addData(new Buffer(fromAliceToBob.notificationOutputs[0], 'hex'))
        .to('14L2fpcYwQQMmJvVJeewyuvdGfi49HmCZY', 100000);

      var x = bitcore.HDPrivateKey(a.xPrivKey);
      txToBob.sign(x.derive('m/0').privateKey);
      var txToBobHex = txToBob.uncheckedSerialize();

      var bob = new PaymentCode(b.paymentCode);
      var payInfo = bob.retrivePaymentInfo(txToBobHex, b.xPrivKey, 1);
      payInfo.xPublicKeys[0].should.equal(a.xPubKey.toString());
      payInfo.hisPc.should.equal(a.paymentCode);

      // Is the given private key correct?
      var p = bitcore.PrivateKey(payInfo.privateKey).publicKey;
      var addr = p.toAddress();
      payInfo.paymentAddress.should.equal(addr.toString());

    });


    describe('Multiple payments(Bob receives notification from Alice)', function() {
      var a = tc1;
      var b = tc2;
 
      var alice = new PaymentCode([a.xPubKey]);
      _.each(_.range(1, 10), function(i) {
        var fromAliceToBob = alice.makePaymentInfo(b.paymentCode, a.xPrivKey, i, 0);
        it('Should decode payment '+i+' (Bobfrom Alice)', function() {

          var txToBob = new bitcore.Transaction()
            .from({
              "txid": "3e46af54b2a79e8a343145e91e4801ea8611a69cd29852ff95e4b547cfd90b7b",
              "vout": 0,
              "scriptPubKey": "76a9145227a227819489ee792a7253d2fe6c764673123288ac",
              "amount": 4.9998
            })
            .addData(new Buffer(fromAliceToBob.notificationOutputs[0], 'hex'))
            .to('14L2fpcYwQQMmJvVJeewyuvdGfi49HmCZY', 100000);

          var x = bitcore.HDPrivateKey(a.xPrivKey);
          txToBob.sign(x.derive('m/0').privateKey);
          var txToBobHex = txToBob.uncheckedSerialize();

          var bob = new PaymentCode(b.paymentCode);
          var payInfo = bob.retrivePaymentInfo(txToBobHex, b.xPrivKey, i);
          payInfo.xPublicKeys[0].should.equal(a.xPubKey.toString());
          payInfo.hisPc.should.equal(a.paymentCode);

          // Is the given private key correct?
          var p = bitcore.PrivateKey(payInfo.privateKey).publicKey;
          var addr = p.toAddress();
          payInfo.paymentAddress.should.equal(addr.toString());
        });
      });
    });
  });
});
