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



```javascript

// Generating a Payment code and its notification address for Alice

var PaymentCode = require('bitcore-payment-code');

// Alice's extended private key: MasterPrivKey

var xPrivKey = MasterPrivKey.derive("m/47'/0'/0'"); // See BIP47 for details
var xPubKey = xPrivKey.hdPublicKey;


var alicePc = new PaymentCode([xPubKey]); // Generate a payment Code
//also, new PaymentCode([xPubKey0, ..., xPubKeyN], m)  // Multisig M-N

var serializedPaymentCode = alicePc.toString(); // PaymentCode to share

var aliceNotificationPubKey = alicePc.publicKey;  
var aliceNotificationAddress = aliceNotificationPubKey.toAddress();


// Making a payment to Bob
var paymentInfo = alice.makePaymentInfo(BobPaymentCode, xPrivKey, index, outpoint);

// Index is the alice->bob payment order
// outpoint is where in the transaction the public key will be exposed

// Sample output:
 { 
  publicKeys: [ '023ded791973898f6892cead1b62ba57b9e5dc6c45aeaf0f20813acec96540cec1' ],
  paymentAddress: '1AJ3gNTaJ96NBDcj4cVmPZVBB7sF9rVA31',
  notificationOutputs: [ '010003874d18c82ce5fa774d3cefa16129159cc893007015e5791c0e1d1edba8d4fec48654656a77d16a1c25aaf61423c56973f71d526aab8a10fcc6cb65f3f21c403d00000000000000000000000000' ],
  notificationAddresses: [ '14L2fpcYwQQMmJvVJeewyuvdGfi49HmCZY' ] }
  }

// Then alice needs to send a notification TX:
// .from should be a valid UTXO



// Then the TX should be broadcasted... And the actual payment sent to `paymentInfo.paymentAddress`
// For future payments, index should be incremented.


// ===================================================
// Bob retrieval of the payment....


// When Bob receives a TX on his notification address:

```

## Contributing

See [CONTRIBUTING.md](https://github.com/bitpay/bitcore/blob/master/CONTRIBUTING.md) on the main bitcore repo for information about how to contribute.

## License

Code released under [the MIT license](https://github.com/bitpay/bitcore/blob/master/LICENSE).

Copyright 2015 BitPay, Inc. Bitcore is a trademark maintained by BitPay, Inc.
