// Parts of this software are based on "cashaddr".
// https://github.com/bitcoin-abc/src/cashaddr.cpp
//
// Copyright (c) 2017 Pieter Wuille
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const cashaddr = require('../lib/utils/cashaddr');
const Address = require('../lib/primitives/address');

const validChecksums = [
  'prefix:x64nx6hz',
  'PREFIX:X64NX6HZ',
  'p:gpf8m4h7',
  'bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn',
  'bchtest:testnetaddress4d6njnut'
];

const validAddresses = [
  [
    'bitcoincash:',
    Buffer.from([
      0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
      0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
    ])
  ],
  [
    'bchtest:1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',
    Buffer.from([
      0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04,
      0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78,
      0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32,
      0x62
    ])
  ],
  [
    'bitcoincash:1pw508d6qejxtdg4y5r3zarvary0c5xw7kw50'
    + '8d6qejxtdg4y5r3zarvary0c5xw7k7grplx',
    Buffer.from([
      0x81, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
      0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
      0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
      0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
    ])
  ],
  [
    'BC1SW50QA3JX3S',
    Buffer.from([
      0x90, 0x02, 0x75, 0x1e
    ])
  ],
  [
  'helloworld',
  Buffer.from([
    0x1f, 0x0d
  ])
  ],
  [
    'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj',
    Buffer.from([
      0x82, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
      0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23
    ])
  ],
  [
    'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy',
    Buffer.from([
      0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
      0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
      0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
      0x33
    ])
  ]
];

const invalidAddresses = [
  'prefix:x32nx6hz',
  'prEfix:x64nx6hz',
  'prefix:x64nx6Hz',
  'pref1x:6m8cxv73',
  'prefix:',
  ':u9wsx07j',
  'pre:fix:x32nx6hz',
  'prefixx64nx6hz'
 ];

function fromAddress(prefix, addr) {
  const dec = cashaddr.decode(addr);

  if (dec.prefix !== prefix)
    throw new Error('Invalid cashaddr prefix or data length.');

  return {
    program: dec.hash
  };
}

function toAddress(prefix, version, program) {
  const ret = cashaddr.encode(prefix, version, program);

  fromAddress(prefix, ret);

  return ret;
}

function caseInsensitive(s1, s2) {
  if (s1.length !== s2.length)
    return false;

  for (let i = 0; i < s1.length; i++) {
    let c1 = s1[i];

    if (c1 >= 'A' && c1 <= 'Z') {
      c1 -= ('A' - 'a');
    }

    let c2 = s2[i];

    if (c2 >= 'A' && c2 <= 'Z') {
      c2 -= ('A' - 'a');
    }

    if (c1 !== c2) {
      return false;
    }
  }

  return true;
}

function createProgram(version, program) {
  const data = Buffer.allocUnsafe(2 + program.length);
  data[0] = version ? version + 0x80 : 0;
  data[1] = program.length;
  program.copy(data, 2);
  return data;
}

describe('CashAddr', function() {
  for (const addr of validChecksums) {
    it(`should have valid checksum for ${addr}`, () => {
      assert(cashaddr.deserialize(addr));
    });
  }

  for (const [addr, script] of validAddresses) {
    it(`should have valid address for ${addr}`, () => {
      let prefix = 'bitcoincash';
      let ret = null;

      try {
        ret = fromAddress(prefix, addr);
      } catch (e) {
        ret = null;
      }

      if (ret === null) {
        prefix = 'tb';
        try {
          ret = fromAddress(prefix, addr);
        } catch (e) {
          ret = null;
        }
      }

      assert(ret !== null);

      const output = createProgram(ret.version, ret.program);
      assert.bufferEqual(output, script);

      const recreate = toAddress(prefix, ret.version, ret.program);
      assert.strictEqual(recreate, addr.toLowerCase());
    });
  }

  for (const addr of invalidAddresses) {
    it(`should have invalid address for ${addr}`, () => {
      assert.throws(() => fromAddress('bitcoincash', addr));
      assert.throws(() => fromAddress('bchtest', addr));
    });
  }

  for (const [addr, script] of validAddresses) {
    it(`should have valid address for ${addr}`, () => {
      let ret = null;

      try {
        ret = Address.fromCashAddr(addr, 'main');
      } catch (e) {
        ret = null;
      }

      if (ret === null) {
        try {
          ret = Address.fromCashAddr(addr, 'testnet');
        } catch (e) {
          ret = null;
        }
      }

      assert(ret !== null);

      const output = createProgram(ret.version, ret.hash);
      assert.bufferEqual(output, script);

      const recreate = ret.toCashAddr();
      assert.strictEqual(recreate, addr.toLowerCase());
    });
  }

  for (const addr of invalidAddresses) {
    it(`should have invalid address for ${addr}`, () => {
      assert.throws(() => Address.fromCashAddr(addr, 'main'));
      assert.throws(() => Address.fromCashAddr(addr, 'testnet'));
    });
  }
});
