/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const encoding = require('../lib/utils/encoding');
const assert = require('./util/assert');
const random = require('../lib/crypto/random');
const util = require('../lib/utils/util');
const consensus = require('../lib/protocol/consensus');
const TX = require('../lib/primitives/tx');
const MTX = require('../lib/primitives/mtx');
const Output = require('../lib/primitives/output');
const Outpoint = require('../lib/primitives/outpoint');
const Script = require('../lib/script/script');
const Opcode = require('../lib/script/opcode');
const Input = require('../lib/primitives/input');
const CoinView = require('../lib/coins/coinview');
const KeyRing = require('../lib/primitives/keyring');
const Address = require('../lib/primitives/address');
const common = require('./util/common');

const validTests = require('./data/tx-valid.json');
const invalidTests = require('./data/tx-invalid.json');
const sighashTests = require('./data/sighash-tests.json');

const tx1 = common.readTX('tx1');
const tx2 = common.readTX('tx2');
const tx3 = common.readTX('tx3');
const tx4 = common.readTX('tx4');
const tx5 = common.readTX('tx5');
const tx6 = common.readTX('tx6');
const tx7 = common.readTX('tx7');

const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const MAX_SAFE_ADDITION = 0xfffffffffffff;

function clearCache(tx, noCache) {
  if (noCache) {
    tx.refresh();
    return;
  }

  const copy = tx.clone();

  assert.bufferEqual(tx.hash(), copy.hash());
}

function parseTXTest(data) {
  const coins = data[0];
  const hex = data[1];
  const names = data[2] || 'NONE';

  let flags = 0;

  for (const name of names.split(',')) {
    const flag = Script.flags[`VERIFY_${name}`];

    if (flag == null)
      throw new Error(`Unknown flag: ${name}.`);

    flags |= flag;
  }

  const view = new CoinView();

  for (const [txid, index, str, amount] of coins) {
    const hash = util.revHex(txid);
    const script = Script.fromString(str);
    const value = parseInt(amount || '0', 10);

    // Ignore the coinbase tests.
    // They should all fail.
    if ((index >>> 0) === 0xffffffff)
      continue;

    const prevout = new Outpoint(hash, index);
    const output = new Output({script, value});

    view.addOutput(prevout, output);
  }

  const raw = Buffer.from(hex, 'hex');
  const tx = TX.fromRaw(raw);

  const coin = view.getOutputFor(tx.inputs[0]);

  return {
    tx: tx,
    flags: flags,
    view: view,
    comments: coin
      ? util.inspectify(coin.script)
      : 'coinbase',
    data: data
  };
}

function parseSighashTest(data) {
  const [txHex, scriptHex, index, type, hash] = data;

  const tx = TX.fromRaw(txHex, 'hex');
  const script = Script.fromRaw(scriptHex, 'hex');

  const expected = util.revHex(hash);

  let hex = type & 3;

  if (type & 0x40)
    hex |= 0x40;

  hex = hex.toString(16);

  if (hex.length % 2 !== 0)
    hex = '0' + hex;

  return {
    tx: tx,
    script: script,
    index: index,
    type: type,
    hash: hash,
    expected: expected,
    hex: hex
  };
}

function createInput(value, view) {
  const hash = random.randomBytes(32).toString('hex');

  const input = {
    prevout: {
      hash: hash,
      index: 0
    }
  };

  const output = new Output();
  output.value = value;

  if (!view)
    view = new CoinView();

  view.addOutput(new Outpoint(hash, 0), output);

  return [input, view];
};

function sigopContext(scriptSig, scriptPubkey) {
  const fund = new TX();

  {
    fund.version = 1;

    const input = new Input();
    fund.inputs.push(input);

    const output = new Output();
    output.value = 1;
    output.script = scriptPubkey;
    fund.outputs.push(output);

    fund.refresh();
  }

  const spend = new TX();

  {
    spend.version = 1;

    const input = new Input();
    input.prevout.hash = fund.hash('hex');
    input.prevout.index = 0;
    input.script = scriptSig;
    spend.inputs.push(input);

    const output = new Output();
    output.value = 1;
    spend.outputs.push(output);

    spend.refresh();
  }

  const view = new CoinView();

  view.addTX(fund, 0);

  return {
    fund: fund,
    spend: spend,
    view: view
  };
}

describe('TX', function() {
  for (const noCache of [false, true]) {
    const suffix = noCache ? 'without cache' : 'with cache';

    it(`should verify non-minimal output ${suffix}`, () => {
      const [tx, view] = tx1.getTX();
      clearCache(tx, noCache);
      assert(tx.verify(view, Script.flags.VERIFY_P2SH));
    });

    it(`should verify tx.version == 0 ${suffix}`, () => {
      const [tx, view] = tx2.getTX();
      clearCache(tx, noCache);
      assert(tx.verify(view, Script.flags.VERIFY_P2SH));
    });

    it(`should verify high S value with only DERSIG enabled ${suffix}`, () => {
      const [tx, view] = tx4.getTX();
      const coin = view.getOutputFor(tx.inputs[0]);
      const flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_DERSIG;
      clearCache(tx, noCache);
      assert(tx.verifyInput(0, coin, flags));
    });

    it(`should verify the coolest tx ever sent ${suffix}`, () => {
      const [tx, view] = tx6.getTX();
      clearCache(tx, noCache);
      assert(tx.verify(view, Script.flags.VERIFY_NONE));
    });

    it(`should count sigops for p2sh multisig`, () => {
      const flags = Script.flags.VERIFY_P2SH;
      const key = KeyRing.generate();
      const pub = key.publicKey;

      const redeem = Script.fromMultisig(1, 2, [pub, pub]);
      const output = Script.fromScripthash(redeem.hash160());

      const input = new Script([
        Opcode.fromInt(0),
        Opcode.fromInt(0),
        Opcode.fromData(redeem.toRaw())
      ]);

      const ctx = sigopContext(input, output);

      assert.strictEqual(ctx.spend.getSigopsCount(ctx.view, flags), 2);
    });

    it(`should return addresses for standard inputs`, () => {
      const [tx, view] = tx2.getTX();
      const inputAddresses = [
        Address.fromBase58('1Wjrrc2DrtB2CXRiPa3c8528fDdNHnQ2K')
      ];

      const inputAddressesView = tx.getInputAddresses(view);
      const inputAddressesNoView = tx.getInputAddresses();

      assert.strictEqual(inputAddresses.length, inputAddressesView.length);
      assert.strictEqual(inputAddresses.length, inputAddressesNoView.length);
    });

    it(`should return correct minFee and roundedFee`, () => {
      const value = 100000000; // 1 btc
      const height = 100;
      const [input, view] = createInput(value);

      // hack height into coinEntry
      const entry = view.getEntry(input.prevout);
      entry.height = height;

      const tx = new TX({
        version: 1,
        inputs: [input],
        outputs: [{
          script: [],
          value: value
        }],
        locktime: 0
      });

      // Priority should be more than FREE_THRESHOLD
      // txsize: 60, value: 1btc
      // freeAfter: 144.250 * txsize = 34.56
      const size = tx.getBaseSize();
      const freeHeight = height + 35;
      const freeAt34 = tx.isFree(view, freeHeight - 1);
      const freeAt34size = tx.isFree(view, freeHeight - 1, tx, size);
      const freeAt35 = tx.isFree(view, freeHeight);
      const freeAt35size = tx.isFree(view, freeHeight, size);

      assert.strictEqual(freeAt34, false);
      assert.strictEqual(freeAt34size, false);
      assert.strictEqual(freeAt35, true);
      assert.strictEqual(freeAt35size, true);
    });

    it(`should return correct minFee, and roundedFee`, () => {
      const value = 100000000; // 1 BTC
      const [input] = createInput(value);
      const tx = new TX({
        version: 1,
        inputs: [input],
        outputs: [{
          script: [],
          value: value
        }],
        locktime: 0
      });

      // 1000 satoshis per kb
      const rate = 1000;
      const size = tx.getBaseSize(); // 60 bytes

      // doesn't round to KB
      assert.strictEqual(tx.getMinFee(size, rate), 60);
      assert.strictEqual(tx.getMinFee(size, rate * 10), 600);
      assert.strictEqual(tx.getMinFee(size * 10, rate), 600);

      // rounds to KB
      assert.strictEqual(tx.getRoundFee(size, rate), 1000);
      //still under KB
      assert.strictEqual(tx.getRoundFee(size * 10, rate), 1000);
      assert.strictEqual(tx.getRoundFee(size, rate * 10), 10000);

      assert.strictEqual(tx.getRoundFee(1000, rate), 1000);
      assert.strictEqual(tx.getRoundFee(1001, rate), 2000);
    });

    it(`should return JSON for tx`, () => {
      const [tx, view] = tx2.getTX();
      const hash = '7ef7cde4e4a7829ea6feaf377c924b36d0958e22'
        + '31a31ff268bd33a59ac9e178';
      const version = 0;
      const locktime = 0;
      const hex = tx2.getRaw().toString('hex');

      // hack for ChainEntry
      const entry = {
        height: 1000,
        hash: 'c82d447db6150d2308d9571c19bc3dc6efde97a8227d9e57bc77ec0900000000',
        time: 1365870306
      };
      const network = 'testnet';
      const index = 0;

      const jsonDefault = tx.getJSON(network);
      const jsonView = tx.getJSON(network, view);
      const jsonEntry = tx.getJSON(network, null, entry);
      const jsonIndex = tx.getJSON(network, null, null, index);
      const jsonAll = tx.getJSON(network, view, entry, index);

      for (const json of [jsonDefault, jsonView, jsonEntry, jsonIndex, jsonAll]) {
        assert.strictEqual(json.hash, hash);
        assert.strictEqual(json.version, version);
        assert.strictEqual(json.locktime, locktime);
        assert.strictEqual(json.hex, hex);
      }

      const fee = 10000;
      const rate = 44247;

      for (const json of [jsonView, jsonAll]) {
        assert.strictEqual(json.fee, fee);
        assert.strictEqual(json.rate, rate);
      }

      const date = '2013-04-13T16:25:06Z';
      for (const json of [jsonEntry, jsonAll]) {
        assert.strictEqual(json.height, entry.height);
        assert.strictEqual(json.block, util.revHex(entry.hash));
        assert.strictEqual(json.time, entry.time);
        assert.strictEqual(json.date, date);
      }

      for (const json of [jsonIndex, jsonAll]) {
        assert.strictEqual(json.index, index);
      }
    });

    for (const json of sighashTests) {
      if (json.length === 1)
        continue;

      const test = parseSighashTest(json);
      const {tx, script, index, type} = test;
      const {hash, hex, expected} = test;

      clearCache(tx, noCache);

      it(`should get sighash of ${hash} (${hex}) ${suffix}`, () => {
        const subscript = script.getSubscript(0).removeSeparators();
        const hash = tx.signatureHash(index, subscript, 0, type, 0);
        assert.strictEqual(hash.toString('hex'), expected);
      });
    }
   }
});
