/*!
 * block.js - block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');
const util = require('../utils/util');
const hash256 = require('bcrypto/lib/hash256');
const merkle = require('bcrypto/lib/merkle');
const consensus = require('../protocol/consensus');
const AbstractBlock = require('./abstractblock');
const TX = require('./tx');
const MerkleBlock = require('./merkleblock');
const Headers = require('./headers');
const Network = require('../protocol/network');
const {encoding} = bio;

/**
 * Block
 * Represents a full block.
 * @alias module:primitives.Block
 * @extends AbstractBlock
 */

class Block extends AbstractBlock {
  /**
   * Create a block.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();

    this.txs = [];

    this._raw = null;
    this._size = -1;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    this.parseOptions(options);

    if (options.txs) {
      assert(Array.isArray(options.txs));
      for (const tx of options.txs) {
        assert(tx instanceof TX);
        this.txs.push(tx);
      }
    }
  }

  /**
   * Instantiate block from options.
   * @param {Object} options
   * @returns {Block}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Clear any cached values.
   * @param {Boolean?} all - Clear transactions.
   */

  refresh(all) {
    this._refresh();

    this._raw = null;
    this._size = -1;

    if (!all)
      return;

    for (const tx of this.txs)
      tx.refresh();
  }

  /**
   * Serialize the block.
   * @returns {Buffer}
   */

  toRaw() {
    return this.frame().data;
  }

  /**
   * Serialize the block.
   * @returns {Buffer}
   */

  toNormal() {
    return this.frameNormal().data;
    return this.toRaw();
  }

  /**
   * Serialize the block.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    if (this.mutable)
      return this.writeNormal(bw);

    const raw = this.frame();
    bw.writeBytes(raw.data);

    return bw;
  }

  /**
   * Serialize the block.
   * @param {BufferWriter} bw
   */

  toNormalWriter(bw) {
    this.writeNormal(bw);
      return bw;
    return this.toWriter(bw);
  }

  /**
   * Get the raw block serialization.
   * @private
   * @returns {RawBlock}
   */

  frame() {
    if (this.mutable) {
      assert(!this._raw);
      return this.frameNormal();
    }

    if (this._raw) {
      assert(this._size >= 0);
      const raw = new RawBlock(this._size);
      raw.data = this._raw;
      return raw;
    }

    const raw = this.frameNormal();

    this._raw = raw.data;
    this._size = raw.size;
    return raw;
  }

  /**
   * Calculate real size of the bytes.
   * @returns {Object} Contains `size`.
   */

  getSizes() {
    if (this.mutable)
      return this.getNormalSizes();
    return this.frame();
  }

  /**
   * Get real block size.
   * @returns {Number} size
   */

  getSize() {
    return this.getSizes().size;
  }

  /**
   * Get base block size.
   * @returns {Number} size
   */

  getBaseSize() {
    const raw = this.getSizes();
    return raw.size;
  }

  /**
   * Test the block's transaction vector against a hash.
   * @param {Hash} hash
   * @returns {Boolean}
   */

  hasTX(hash) {
    return this.indexOf(hash) !== -1;
  }

  /**
   * Find the index of a transaction in the block.
   * @param {Hash} hash
   * @returns {Number} index (-1 if not present).
   */

  indexOf(hash) {
    for (let i = 0; i < this.txs.length; i++) {
      const tx = this.txs[i];
      if (tx.hash('hex') === hash)
        return i;
    }

    return -1;
  }

  /**
   * Calculate merkle root. Returns null
   * if merkle tree has been malleated.
   * @param {String?} enc - Encoding, can be `'hex'` or null.
   * @returns {Hash|null}
   */

  createMerkleRoot(enc) {
    const leaves = [];

    for (const tx of this.txs)
      leaves.push(tx.hash());

    const [root, malleated] = merkle.createRoot(hash256, leaves);

    if (malleated)
      return null;

    return enc === 'hex' ? root.toString('hex') : root;
  }

  /**
   * Create a nonce (for mining).
   * @returns {Buffer}
   */

  createNonce() {
    return Buffer.from(consensus.ZERO_HASH);
  }

  /**
   * Calculate commitment hash (the root of the
   * Merkle tree hashed with the Nonce).
   * @param {String?} enc - Encoding, can be `'hex'` or null.
   * @returns {Hash}
   */

  createCommitmentHash(enc) {
    const nonce = this.getNonce();
    const leaves = [];

    assert(nonce, 'No nonce present.');

    leaves.push(consensus.ZERO_HASH);

    for (let i = 1; i < this.txs.length; i++) {
      const tx = this.txs[i];
      leaves.push(tx.hash());
    }

    const [root] = merkle.createRoot(hash256, leaves);

    // Note: malleation check ignored here.
    // assert(!malleated);

    const hash = hash256.root(root, nonce);

    return enc === 'hex'
      ? hash.toString('hex')
      : hash;
  }

  /**
   * Retrieve the merkle root from the block header.
   * @param {String?} enc
   * @returns {Hash}
   */

  getMerkleRoot(enc) {
    if (enc === 'hex')
      return this.merkleRoot;
    return Buffer.from(this.merkleRoot, 'hex');
  }

  /**
   * Retrieve the nonce from the
   * coinbase's vector (if present).
   * @returns {Buffer|null}
   */

  getNonce() {
    if (this.txs.length === 0)
      return null;

    const coinbase = this.txs[0];

    if (coinbase.inputs.length !== 1)
      return null;

    const input = coinbase.inputs[0];

    if (input.items.length !== 1)
      return null;

    if (input.items[0].length !== 32)
      return null;

    return input.items[0];
  }

  /**
   * Retrieve the commitment hash
   * from the coinbase's outputs.
   * @param {String?} enc
   * @returns {Hash|null}
   */

  getCommitmentHash(enc) {
    if (this.txs.length === 0)
      return null;

    const coinbase = this.txs[0];

    let hash = null;

    for (let i = coinbase.outputs.length - 1; i >= 0; i--) {
      const output = coinbase.outputs[i];
      if (output.script.isCommitment()) {
        hash = output.script.getCommitment();
        break;
      }
    }

    if (!hash)
      return null;

    return enc === 'hex'
      ? hash.toString('hex')
      : hash;
  }

  /**
   * Do non-contextual verification on the block. Including checking the block
   * size, the coinbase and the merkle root. This is consensus-critical.
   * @returns {Boolean}
   */

  verifyBody() {
    const [valid] = this.checkBody();
    return valid;
  }

  /**
   * Do non-contextual verification on the block. Including checking the block
   * size, the coinbase and the merkle root. This is consensus-critical.
   * @returns {Array} [valid, reason, score]
   */

  checkBody() {
    // Check merkle root.
    const root = this.createMerkleRoot('hex');

    // If the merkle is mutated,
    // we have duplicate txs.
    if (!root)
      return [false, 'bad-txns-duplicate', 100];

    if (this.merkleRoot !== root)
      return [false, 'bad-txnmrklroot', 100];

    // Check base size.
    if (this.txs.length === 0
        || this.txs.length > consensus.ONE_MEGABYTE
        || this.getBaseSize() > consensus.MAX_BLOCK_SIZE) {
      return [false, 'bad-blk-length', 100];
    }

    // First TX must be a coinbase.
    if (this.txs.length === 0 || !this.txs[0].isCoinbase())
      return [false, 'bad-cb-missing', 100];

    let sigops = 0;

    for (let i = 0; i < this.txs.length; i++) {
      const tx = this.txs[i];

      // The rest of the txs must not be coinbases.
      if (i > 0 && tx.isCoinbase())
        return [false, 'bad-cb-multiple', 100];

      // Sanity checks.
      const [valid, reason, score] = tx.checkSanity();

      if (!valid)
        return [valid, reason, score];

      // Count legacy sigops (do not count scripthash).
      sigops += tx.getLegacySigops();

      const maxSigopsCount = consensus.getMaxBlockSigopsCount(this.getBaseSize());

      if (sigops > maxSigopsCount)
        return [false, 'bad-blk-sigops', 100];
    }

    return [true, 'valid', 0];
  }

  /**
   * Retrieve the coinbase height from the coinbase input script.
   * @returns {Number} height (-1 if not present).
   */

  getCoinbaseHeight() {
    if (this.version < 2)
      return -1;

    if (this.txs.length === 0)
      return -1;

    const coinbase = this.txs[0];

    if (coinbase.inputs.length === 0)
      return -1;

    return coinbase.inputs[0].script.getCoinbaseHeight();
  }

  /**
   * Get the "claimed" reward by the coinbase.
   * @returns {Amount} claimed
   */

  getClaimed() {
    assert(this.txs.length > 0);
    assert(this.txs[0].isCoinbase());
    return this.txs[0].getOutputValue();
  }

  /**
   * Get all unique outpoint hashes in the
   * block. Coinbases are ignored.
   * @returns {Hash[]} Outpoint hashes.
   */

  getPrevout() {
    const prevout = Object.create(null);

    for (let i = 1; i < this.txs.length; i++) {
      const tx = this.txs[i];

      for (const input of tx.inputs)
        prevout[input.prevout.hash] = true;
    }

    return Object.keys(prevout);
  }

  /**
   * Inspect the block and return a more
   * user-friendly representation of the data.
   * @returns {Object}
   */

  inspect() {
    return this.format();
  }

  /**
   * Inspect the block and return a more
   * user-friendly representation of the data.
   * @param {CoinView} view
   * @param {Number} height
   * @returns {Object}
   */

  format(view, height) {
    const commitmentHash = this.getCommitmentHash('hex');
    return {
      hash: this.rhash(),
      height: height != null ? height : -1,
      size: this.getSize(),
      date: util.date(this.time),
      version: this.version.toString(16),
      prevBlock: util.revHex(this.prevBlock),
      merkleRoot: util.revHex(this.merkleRoot),
      commitmentHash: commitmentHash
        ? util.revHex(commitmentHash)
        : null,
      time: this.time,
      bits: this.bits,
      nonce: this.nonce,
      txs: this.txs.map((tx, i) => {
        return tx.format(view, null, i);
      })
    };
  }

  /**
   * Convert the block to an object suitable
   * for JSON serialization.
   * @returns {Object}
   */

  toJSON() {
    return this.getJSON();
  }

  /**
   * Convert the block to an object suitable
   * for JSON serialization. Note that the hashes
   * will be reversed to abide by bitcoind's legacy
   * of little-endian uint256s.
   * @param {Network} network
   * @param {CoinView} view
   * @param {Number} height
   * @param {Number} depth
   * @returns {Object}
   */

  getJSON(network, view, height, depth) {
    network = Network.get(network);
    return {
      hash: this.rhash(),
      height: height,
      depth: depth,
      version: this.version,
      prevBlock: util.revHex(this.prevBlock),
      merkleRoot: util.revHex(this.merkleRoot),
      time: this.time,
      bits: this.bits,
      nonce: this.nonce,
      txs: this.txs.map((tx, i) => {
        return tx.getJSON(network, view, null, i);
      })
    };
  }

  /**
   * Inject properties from json object.
   * @private
   * @param {Object} json
   */

  fromJSON(json) {
    assert(json, 'Block data is required.');
    assert(Array.isArray(json.txs));

    this.parseJSON(json);

    for (const tx of json.txs)
      this.txs.push(TX.fromJSON(tx));

    return this;
  }

  /**
   * Instantiate a block from a jsonified block object.
   * @param {Object} json - The jsonified block object.
   * @returns {Block}
   */

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromReader(br) {
    br.start();

    this.readHead(br);

    const count = br.readVarint();

    for (let i = 0; i < count; i++) {
      const tx = TX.fromReader(br);
      this.txs.push(tx);
    }

    if (!this.mutable) {
      this._raw = br.endData();
      this._size = this._raw.length;
    }

    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate a block from a serialized Buffer.
   * @param {Buffer} data
   * @param {String?} enc - Encoding, can be `'hex'` or null.
   * @returns {Block}
   */

  static fromReader(data) {
    return new this().fromReader(data);
  }

  /**
   * Instantiate a block from a serialized Buffer.
   * @param {Buffer} data
   * @param {String?} enc - Encoding, can be `'hex'` or null.
   * @returns {Block}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }

  /**
   * Convert the Block to a MerkleBlock.
   * @param {Bloom} filter - Bloom filter for transactions
   * to match. The merkle block will contain only the
   * matched transactions.
   * @returns {MerkleBlock}
   */

  toMerkle(filter) {
    return MerkleBlock.fromBlock(this, filter);
  }

  /**
   * Serialze block.
   * @private
   * @param {BufferWriter?} writer
   * @returns {Buffer}
   */

  writeNormal(bw) {
    this.writeHead(bw);

    bw.writeVarint(this.txs.length);

    for (const tx of this.txs)
      tx.toNormalWriter(bw);

    return bw;
  }

  /**
   * Serialze block.
   * @private
   * @param {BufferWriter?} writer
   * @returns {Buffer}
   */

  frameNormal() {
    const raw = this.getNormalSizes();
    const bw = bio.write(raw.size);
    this.writeNormal(bw);
    raw.data = bw.render();
    return raw;
  }

  /**
   * Convert the block to a headers object.
   * @returns {Headers}
   */

  toHeaders() {
    return Headers.fromBlock(this);
  }

  /**
   * Get real block size.
   * @returns {RawBlock}
   */

  getNormalSizes() {
    let size = 0;

    size += 80;
    size += encoding.sizeVarint(this.txs.length);

    for (const tx of this.txs)
      size += tx.getBaseSize();

    return new RawBlock(size, 0);
  }

  /**
   * Test whether an object is a Block.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isBlock(obj) {
    return obj instanceof Block;
  }
}

/*
 * Helpers
 */

class RawBlock {
  constructor(size) {
    this.data = null;
    this.size = size;
  }
}

/*
 * Expose
 */

module.exports = Block;
