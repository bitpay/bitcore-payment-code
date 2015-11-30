<img src="http://bitcore.io/css/images/module-payment-protocol.png" alt="bitcore payment protocol" height="35">
BIP47 Payment Code support for bitcore
=======

[![NPM Package](https://img.shields.io/npm/v/bitcore-payment-code.svg?style=flat-square)](https://www.npmjs.org/package/bitcore-payment-code)
[![Build Status](https://img.shields.io/travis/bitpay/bitcore-payment-code.svg?branch=master&style=flat-square)](https://travis-ci.org/bitpay/bitcore-payment-code)
[![Coverage Status](https://img.shields.io/coveralls/bitpay/bitcore-payment-code.svg?style=flat-square)](https://coveralls.io/r/bitpay/bitcore-payment-code)

A module for [bitcore](https://github.com/bitpay/bitcore) that implements [Payment Code](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki)

## Getting Started

This library is distributed in both the npm and bower packaging systems.

```sh
npm install bitcore-payment-code
bower install bitcore-payment-code
```

TODO: There are many examples of how to use it on the developer guide [section for payment protocol](http://bitcore.io/guide/paymentprotocol.html). 

For example, the following code would verify a payment request:

```javascript

// Generating a Payment code and its notification address for Alice

var PaymentCode = require('bitcore-payment-code');

// Alice extended private key: MasterPrivKey

var xPrivKey = MasterPrivKey.derive("m/47'/0'/0'"); // See BIP47 for details
var xPubKey = xPrivKey.hdPublicKey;


var alicePc = new PaymentCode([xPubKey]); // Generate a payment Code
//also, new PaymentCode([xPubKey0, ..., xPubKeyN], m)  // Multisig M-N

var serializedPaymentCode = alicePc.toString(); // PaymentCode to share

var aliceNotificationPubKey = alicePc.publicKey;  
var aliceNotificationAddress = aliceNotificationPubKey.toAddress();


// Making a payment to Bob
var paymentInfo =  alice.makePaymentInfo(BobPaymentCode, xPrivKey, index, outpoint); 

// Index is the alice->bob payment order
// output is where in the transaction the public key will be exposed

// Output sample:
 { 
  publicKeys: [ '023ded791973898f6892cead1b62ba57b9e5dc6c45aeaf0f20813acec96540cec1' ],
  paymentAddress: '1AJ3gNTaJ96NBDcj4cVmPZVBB7sF9rVA31',
  notificationOutputs: [ '010003874d18c82ce5fa774d3cefa16129159cc893007015e5791c0e1d1edba8d4fec48654656a77d16a1c25aaf61423c56973f71d526aab8a10fcc6cb65f3f21c403d00000000000000000000000000' ],
  notificationAddresses: [ '14L2fpcYwQQMmJvVJeewyuvdGfi49HmCZY' ] }
  }

// The alice needs to send a notification TX:
// .from should be a valid UTXO
  var txToBob = new bitcore.Transaction()
    .from({
      "txid": "xxx",
      "vout": 0,
      "scriptPubKey": "76a9145227a227819489ee792a7253d2fe6c764673123288ac",
      "amount": 1.00,
    })
    .addData(new Buffer(paymentInfo.notificationOutputs[0], 'hex'))
    .to(paymentInfo.notificationAddresses[0], 10000);

  var x = bitcore.HDPrivateKey(a.xPrivKey);
  txToBob.sign(x.derive('m/0').privateKey);

// Then the TX should be broadcasted... And the actual payment sent to `paymentInfo.paymentAddress`
// For future payments, index should be incremented.


// ===================================================
// Bob retrival of the payment....

var xPrivKey = MasterPrivKey.derive("m/47'/0'/0'"); // See BIP47 for details
var xPubKey = xPrivKey.hdPublicKey;
var bobPc = new PaymentCode([xPubKey]); // Generate a payment Code

// When Bob receives a TX on his notification address:
  var payInfo = bobPc.retrivePaymentInfo(txHex, xPrivKey, index);

// Sample output:
{ publicKey: '023ded791973898f6892cead1b62ba57b9e5dc6c45aeaf0f20813acec96540cec1',
  paymentAddress: '1AJ3gNTaJ96NBDcj4cVmPZVBB7sF9rVA31',
  privateKey: 'dfd5f81894cc8d2d5af3cdc34ec967a20e691ea3172e939287b5aaa526188b00',
  hisPc: 'PM8TJgiBF3npDfpxaKqU9W8iDL3T9v8j1RMVqoLqNFQcFdJ6PqjmcosHEQsHMGwe3CcgSdPz46NvJkNpHWym7b3XPF2CMZvcMT5vCvTnh58zpw529bGn',
  xPublicKeys: [ 'xpub661MyMwAqRbcFFQ6DKngUbHJ8EwExPdKdRkdDpEnppVBzeLCiAHqGnyXseaogVEDKjAgutwm4cdrwgC5LJosUcHvpqES1ZRhgkYg8LHH6rL' ] }

// The payment address index `index` is given, along with the proper privak key to retrive it.

```

## Contributing

See [CONTRIBUTING.md](https://github.com/bitpay/bitcore/blob/master/CONTRIBUTING.md) on the main bitcore repo for information about how to contribute.

## License

Code released under [the MIT license](https://github.com/bitpay/bitcore/blob/master/LICENSE).

Copyright 2015 BitPay, Inc. Bitcore is a trademark maintained by BitPay, Inc.
