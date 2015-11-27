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

describe('PaymentCode', function() {

  it('should be able to create class', function() {
    should.exist(PaymentCode);
  });

  describe('Constructor', function() {

    it('Should create a code and notification address from given xprivkey', function() {
      var xPrivKey = new bitcore.HDPrivateKey('xprv9s21ZrQH143K2mKd7JFg7TLZaD6kYvuUGCq2RRqBGUxD7r14Acyaizf42LiGpSJxGCd8AKh4KXowS348PuhUxpTx45yw5iUc8ktXrWXLRnR');
      var xPubKey = xPrivKey.hdPublicKey;
      var pc = new PaymentCode(xPubKey);
      pc.toString().should.equal('PM8TJgiBF3npDfpxaKqU9W8iDL3T9v8j1RMVqoLqNFQcFdJ6PqjmcosHEQsHMGwe3CcgSdPz46NvJkNpHWym7b3XPF2CMZvcMT5vCvTnh58zpw529bGn');

      _.map(pc.notificationPublicKeys, function(x) {
        return x.toString();
      }).should.deep.equal(['03032f6a9fa2e495b056755dfda82b288e22a71851032c02450e6ebbbef1695191']);


      _.map(pc.notificationAddresses, function(x) {
        return x.toString();
      }).should.deep.equal(['18VPtWU95XYkKu47nrARz6hpQEzZmBPJMu']);

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
      var pc = new PaymentCode('PM8TJgiBF3npDfpxaKqU9W8iDL3T9v8j1RMVqoLqNFQcFdJ6PqjmcosHEQsHMGwe3CcgSdPz46NvJkNpHWym7b3XPF2CMZvcMT5vCvTnh58zpw529bGn');


      _.map(pc.notificationPublicKeys, function(x) {
        return x.toString();
      }).should.deep.equal(['03032f6a9fa2e495b056755dfda82b288e22a71851032c02450e6ebbbef1695191']);


      _.map(pc.notificationAddresses, function(x) {
        return x.toString();
      }).should.deep.equal(['18VPtWU95XYkKu47nrARz6hpQEzZmBPJMu']);

    });
  });

});
