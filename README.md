<img src="http://bitcore.io/css/images/module-payment-protocol.png" alt="bitcore payment protocol" height="35">
BIP47 Payment Codes support for bitcore
=======

[![NPM Package](https://img.shields.io/npm/v/bitcore-payment-codes.svg?style=flat-square)](https://www.npmjs.org/package/bitcore-payment-codes)
[![Build Status](https://img.shields.io/travis/bitpay/bitcore-payment-codes.svg?branch=master&style=flat-square)](https://travis-ci.org/bitpay/bitcore-payment-codes)
[![Coverage Status](https://img.shields.io/coveralls/bitpay/bitcore-payment-codes.svg?style=flat-square)](https://coveralls.io/r/bitpay/bitcore-payment-codes)

A module for [bitcore](https://github.com/bitpay/bitcore) that implements [Payment Codes](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki)

## Getting Started

This library is distributed in both the npm and bower packaging systems.

```sh
npm install bitcore-payment-codes
bower install bitcore-payment-codes
```

TODO: There are many examples of how to use it on the developer guide [section for payment protocol](http://bitcore.io/guide/paymentprotocol.html). 

For example, the following code would verify a payment request:

```javascript

// Generating a Payment code and its notification address

var PaymentCodes = require('bitcore-payment-codes');

// xPubKey need to be previously derived to m/47'/0'/0' from master
var myPc = new PaymentCode(xPubKey); // Generate a payment Code
//also, new PaymentCode(xPubKey) 
//also, new PaymentCode(xPubKey) 
//also, new PaymentCode([xPubkeys], m) 

var serializedPaymentCode = myPc.toString(); // PaymentCode to share

var publicKey = myPc.publicKey;   // Get the notification address public key
var notificationAddress = publicKey.toAddress();

// Making a payment
var hisPc = new PaymentCode(code);
var notificationAddress = hisPc.getNotificationAddress();
var address = hisPc.getPaymentAddress(index);

var output = myPc.makeNotificationOutput(hisPc, xPrivKey);  // OP_RETURN content
// also myPc.makeNotificationOutput(hisPc, privKey); 


// Refunds
var pc2 = myPc.fromNotificationOuput(tx, xPrivKey); // Extract the payer's payment code from a notification output
// also,  myPc.fromNotificationOuput(tx, privKey);

var index = 0;
pc2.getPaymentAddress(index); // P2PKH address to make a payment.



```

## Contributing

See [CONTRIBUTING.md](https://github.com/bitpay/bitcore/blob/master/CONTRIBUTING.md) on the main bitcore repo for information about how to contribute.

## License

Code released under [the MIT license](https://github.com/bitpay/bitcore/blob/master/LICENSE).

Copyright 2015 BitPay, Inc. Bitcore is a trademark maintained by BitPay, Inc.
