/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const Mempool = require('../lib/mempool/mempool');
const MempoolEntry = require('../lib/mempool/mempoolentry');
const WorkerPool = require('../lib/workers/workerpool');
const Chain = require('../lib/blockchain/chain');
const MTX = require('../lib/primitives/mtx');
const Script = require('../lib/script/script');
const Coin = require('../lib/primitives/coin');
const Address = require('../lib/primitives/address');
const KeyRing = require('../lib/primitives/keyring');
const Outpoint = require('../lib/primitives/outpoint');
const MemWallet = require('./util/memwallet');
const SIGHASH_FORKID = Script.hashType.FORKID;

const ONE_HASH = Buffer.alloc(32, 0x00);
ONE_HASH[0] = 0x01;

const workers = new WorkerPool({
  enabled: true
});
const chain = new Chain({
  db: 'memory',
  workers
});
const mempool = new Mempool({
  chain,
  db: 'memory',
  workers
});

const wallet = new MemWallet();

function dummyInput(script, hash) {
  const coin = new Coin();
  coin.height = 0;
  coin.value = 0;
  coin.script = script;
  coin.hash = hash;
  coin.index = 0;

  const fund = new MTX();
  fund.addCoin(coin);
  fund.addOutput(script, 70000);

  const [tx, view] = fund.commit();

  const entry = MempoolEntry.fromTX(tx, view, 0);

  mempool.trackEntry(entry, view);

  return Coin.fromTX(fund, 0, -1);
}

describe('Mempool', function() {
  this.timeout(5000);

  it('should open mempool', async () => {
    await workers.open();
    await chain.open();
    await mempool.open();
    chain.state.flags |= Script.flags.VERIFY_SIGHASH_FORKID;
  });

  it(`should handle incoming orphans and TXs`, async () => {
    const key = KeyRing.generate();

    const t1 = new MTX();
    t1.addOutput(wallet.getAddress(), 50000);
    t1.addOutput(wallet.getAddress(), 10000);

    const script = Script.fromPubkey(key.publicKey);

    t1.addCoin(dummyInput(script, ONE_HASH.toString('hex')));

    const sig = t1.signature(0, script, 70000, key.privateKey, SIGHASH_FORKID, 0);

    t1.inputs[0].script = Script.fromItems([sig]);

    // balance: 51000
    wallet.sign(t1);

    const t2 = new MTX();
    t2.addTX(t1, 0); // 50000
    t2.addOutput(wallet.getAddress(), 20000);
    t2.addOutput(wallet.getAddress(), 20000);

    // balance: 49000
    wallet.sign(t2);

    const t3 = new MTX();
    t3.addTX(t1, 1);
    t3.addTX(t2, 0);
    t3.addOutput(wallet.getAddress(), 23000);

    wallet.sign(t3);

    const t4 = new MTX();
    t4.addTX(t2, 1);
    t4.addTX(t3, 0);
    t4.addOutput(wallet.getAddress(), 11000);
    t4.addOutput(wallet.getAddress(), 11000);

    // balance: 22000
    wallet.sign(t4);

    const f1 = new MTX();
    f1.addTX(t4, 1); // 11000
    f1.addOutput(new Address(), 9000);

    wallet.sign(f1);

    const fake = new MTX();
    fake.addTX(t1, 1);  // 1000 (already redeemed)
    fake.addOutput(wallet.getAddress(), 6000); // 6000 instead of 500

    // Script inputs but do not sign
    wallet.template(fake);

    // Fake signature
    const input = fake.inputs[0];
    input.script.setData(0, Buffer.alloc(73, 0x00));
    input.script.compile();
    // balance: 11000
    {
      await mempool.addTX(fake.toTX());
      await mempool.addTX(t4.toTX());

      const balance = mempool.getBalance();
      assert.strictEqual(balance, 70000);
    }

    {
      await mempool.addTX(t1.toTX());

      const balance = mempool.getBalance();
      assert.strictEqual(balance, 60000);
  }

    {
      await mempool.addTX(t2.toTX());

      const balance = mempool.getBalance();
      assert.strictEqual(balance, 50000);
    }

    {
      await mempool.addTX(t3.toTX());

      const balance = mempool.getBalance();
      assert.strictEqual(balance, 22000);
    }

    {
      await mempool.addTX(f1.toTX());

      const balance = mempool.getBalance();
      assert.strictEqual(balance, 20000);
    }

    const txs = mempool.getHistory();
    assert(txs.some((tx) => {
      return tx.hash('hex') === f1.hash('hex');
    }));
  });

  it(`should destroy mempool`, async () => {
    await mempool.close();
    await chain.close();
    await workers.close();
  });
})


