/*!
 * cashaddr.js - cashaddr for bcash
 * Copyright (c) 2018, Jonatan Gonzalez (MIT License).
 * https://github.com/bcash-org/bcash
 *
 * Parts of this software are based on "bech32".
 * https://github.com/bitcoin/bitcoin/src/bech32.cpp
 *
 * Copyright (c) 2017 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

'use strict';

const native = require('../native').binding;

/**
 * @module utils/cashaddr
 */

const POOL65 = Buffer.allocUnsafe(65);
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
];

/**
 * Update checksum.
 * @ignore
 * @param {Number} chk
 * @returns {Number}
 */

function polymod(c) {
  const c0 = c >>> 35;
  return ((c & 0x07ffffffff) << 5)
    ^ (-((c0 >> 0) & 1) & 0x98f2bc8e61)
    ^ (-((c0 >> 1) & 1) & 0x79b76d99e2)
    ^ (-((c0 >> 2) & 1) & 0xf33e5fb3c4)
    ^ (-((c0 >> 3) & 1) & 0xae2eabe2a8)
    ^ (-((c0 >> 4) & 1) & 0x1e4f43e470);
}

/**
 * Encode prefix and data as a cashaddr string.
 * @ignore
 * @param {String} prefix
 * @param {Buffer} data
 * @returns {String}
 */

function serialize(prefix, data) {
  let chk = 1;
  let i;

  for (i = 0; i < prefix.length; i++) {
    const ch = prefix.charCodeAt(i);

    if ((ch >> 5) === 0)
      throw new Error('Invalid cashaddr character.');

    chk = polymod(chk) ^ (ch >> 5);
  }

  if (i + 7 + data.length > 90)
    throw new Error('Invalid cashaddr data length.');

  chk = polymod(chk);

  let str = '';

  for (let i = 0; i < prefix.length; i++) {
    const ch = prefix.charCodeAt(i);
    chk = polymod(chk) ^ (ch & 0x1f);
    str += prefix[i];
  }

  str += '1';

  for (let i = 0; i < data.length; i++) {
    const ch = data[i];

    if ((ch >> 5) !== 0)
      throw new Error('Invalid cashaddr value.');

    chk = polymod(chk) ^ ch;
    str += CHARSET[ch];
  }

  for (let i = 0; i < 8; i++)
    chk = polymod(chk);

  chk ^= 1;

  for (let i = 0; i < 8; i++)
    // Conver the 5-bit groups in mod to checksum values.
    str += CHARSET[(chk >>> (5 * (7 - i))) & 0x1f];

  return str;
}

/**
 * Decode a cashaddr string.
 * @param {String} str
 * @returns {Array} [prefix, data]
 */

function deserialize(str, prefix) {
  let dlen = 0;

  if (str.length < 8 || str.length > 90)
    throw new Error('Invalid cashaddr string length.');

  while (dlen < str.length && str[(str.length - 1) - dlen] !== '1')
    dlen++;

  const hlen = str.length - (1 + dlen);

  if (hlen < 1 || dlen < 6)
    throw new Error('Invalid cashaddr data length.');

  dlen -= 6;

  const data = Buffer.allocUnsafe(dlen);

  let chk = 1;
  let lower = false;
  let upper = false;
  let number = false;
  let prefix = '';

  for (let i = 0; i < hlen; i++) {
    let ch = str.charCodeAt(i);

    if (ch < 0x21 || ch > 0x7f)
      throw new Error('Invalid cashaddr character.');

    if (ch >= 0x61 && ch <= 0x7a) {
      lower = true;
    } else if (ch >= 0x41 && ch <= 0x5a) {
      upper = true;
      ch = (ch - 0x41) + 0x61;
    }

    prefix += String.fromCharCode(ch);
    chk = polymod(chk) ^ (ch >> 5);
  }

  chk = polymod(chk);

  let i;
  for (i = 0; i < hlen; i++)
    chk = polymod(chk) ^ (str.charCodeAt(i) & 0x1f);

  i++;

  while (i < str.length) {
    const ch = str.charCodeAt(i);
    const v = (ch & 0x80) ? -1 : TABLE[ch];

    if (ch >= 0x61 && ch <= 0x7a)
      lower = true;
    else if (ch >= 0x41 && ch <= 0x5a)
      upper = true;

    if (ch >= 0x0 && ch <= 0x9)
      number = true;

    if (v === -1)
      throw new Error('Invalid cashaddr character.');

    chk = polymod(chk) ^ v;

    if (i + 8 < str.length)
      data[i - (1 + hlen)] = v;

    i++;
  }

  if (lower && upper)
    throw new Error('Invalid cashaddr casing.');

  if (chk !== 1)
    throw new Error('Invalid cashaddr checksum.');

  return [prefix, data.slice(0, dlen)];
}

/**
 * Convert serialized data to bits,
 * suitable to be serialized as cashaddr.
 * @param {Buffer} data
 * @param {Buffer} output
 * @param {Number} frombits
 * @param {Number} tobits
 * @param {Number} pad
 * @param {Number} off
 * @returns {Buffer}
 */

function convert(data, output, frombits, tobits, pad, off) {
  const maxv = (1 << tobits) - 1;
  let acc = 0;
  let bits = 0;
  let j = 0;

  if (pad !== -1)
    output[j++] = pad;

  for (let i = off; i < data.length; i++) {
    const value = data[i];

    if ((value >> frombits) !== 0)
      throw new Error('Invalid cashaddr bits.');

    acc = (acc << frombits) | value;
    bits += frombits;

    while (bits >= tobits) {
      bits -= tobits;
      output[j++] = (acc >>> bits) & maxv;
    }
  }

  if (pad !== -1) {
    if (bits > 0)
      output[j++] = (acc << (tobits - bits)) & maxv;
  } else {
    if (bits >= frombits || ((acc << (tobits - bits)) & maxv))
      throw new Error('Invalid cashaddr bits.');
  }

  return output.slice(0, j);
}

function PackAddr(data, type) {
  assert(typeof type === 'string');
  let version = (type << 3);
  let encoded = 0;

  switch(data * 8) {
    case 0xa0:
      encoded = 0x0;
      break;
    case 0xc0:
      encoded = 0x1;
      break;
    case 0xe0:
      encoded = 0x2;
      break;
    case 0x100:
      encoded = 0x3;
      break;
    case 0x140:
      encoded = 0x4;
      break;
    case 0x180:
      encoded = 0x5;
      break;
    case 0x1c0:
      encoded = 0x6;
      break;
    case 0x400:
      encoded = 0x7;
      break;
    default: throw new Error('Error packing bits:');
  }
}

/**
 * Serialize data to cashaddr address.
 * @param {String} prefix
 * @param {Number} version
 * @param {Buffer} hash
 * @returns {String}
 */

function encode(prefix, version, hash) {
  const output = POOL65;

  if (version < 0 || version > 16)
    throw new Error('Invalid cashaddr version.');

  if (hash.length < 2 || hash.length > 40)
    throw new Error('Invalid cashaddr data length.');

  (((prefix + 1) * 8 + 4) / 5);
  const data = convert(hash, output, 8, 5, version, 0);

  return serialize(prefix, data);
}

if (native)
  encode = native.toBech32;

/**
 * Deserialize data from cashaddr address.
 * @param {String} str
 * @returns {Object}
 */

function decode(str) {
  const [prefix, data] = deserialize(str);

  if (data.length === 0 || data.length > 65)
    throw new Error('Invalid cashaddr data length.');

  if (data[0] > 16)
    throw new Error('Invalid cashaddr version.');

  const version = data[0];
  const output = data;
  const hash = convert(data, output, 5, 8, -1, 1);

  if (hash.length < 2 || hash.length > 40)
    throw new Error('Invalid cashaddr data length.');

  return new AddrResult(prefix, version, hash);
}

if (native)
  decode = native.fromBech32;

/**
 * AddrResult
 * @constructor
 * @private
 * @param {String} prefix
 * @param {Number} version
 * @param {Buffer} hash
 * @property {String} prefix
 * @property {Number} version
 * @property {Buffer} hash
 */

function AddrResult(prefix, version, hash) {
  this.prefix = prefix;
  this.version = version;
  this.hash = hash;
}

/*
 * Expose
 */

exports.polymod = polymod;
exports.deserialize = deserialize;
exports.serialize = serialize;
exports.convert = convert;
exports.encode = encode;
exports.decode = decode;
