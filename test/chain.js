// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const path = require('path');
const { createRequire } = require('module');
const crypto = require('crypto');

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i += 1) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}
function hrpExpand(hrp) {
  const out = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}
function convertBits(data, from, to) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const v of data) {
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (bits > 0) out.push((acc << (to - bits)) & maxv);
  return out;
}
function encode(hrp, bytes) {
  const h = hrp.toLowerCase();
  const data = convertBits(bytes, 8, 5);
  const values = hrpExpand(h).concat(data, [0, 0, 0, 0, 0, 0]);
  const mod = polymod(values) ^ 0x2bc830a3;
  const checksum = [];
  for (let p = 0; p < 6; p += 1) checksum.push((mod >> (5 * (5 - p))) & 31);
  return (h + '1' + data.concat(checksum).map((d) => CHARSET[d]).join('')).toUpperCase();
}

function qstampRoot(sdkDir) {
  return path.dirname(require.resolve('@quantovainc/qstamp/package.json', { paths: [sdkDir] }));
}

let latest = 0;

function makeChain(sdkDir, opts) {
  const base = qstampRoot(sdkDir);
  const qstamp = createRequire(path.join(base, 'package.json'))('./');
  const wire = createRequire(path.join(base, 'package.json'))('./lib/wire');
  const net = qstamp.NETWORKS.testnet;
  const o = opts || {};
  const chain = {
    chainId: net.chainId,
    genesis: net.genesis,
    contract: net.contract,
    height: 1000,
    time: o.time || Math.max(Math.floor(Date.now() / 1000), latest + 1),
    txs: new Map(),
    events: new Map(),
    blocks: new Map(),
    nextBlockTime: null,
    core: createRequire(path.join(base, 'package.json'))('@quantovainc/qcore').core,
  };
  chain.height = Math.max(chain.height, (chain.time - net.genesisTime) * 5);
  function newBlock(t) {
    chain.height += 1;
    chain.time = t === undefined ? Math.max(chain.time, Math.floor(Date.now() / 1000)) : t;
    if (t === undefined) latest = Math.max(latest, chain.time);
    const id = encode('QBK', crypto.randomBytes(32));
    chain.blocks.set(chain.height, { block: id, height: chain.height, time: chain.time });
    chain.events.set(chain.height, []);
    return chain.blocks.get(chain.height);
  }
  newBlock(chain.time);
  chain.newBlock = newBlock;
  chain.setTime = (t) => newBlock(t);

  function submitCall(from, to, argsHex) {
    const raw = Buffer.from(argsHex, 'hex');
    const sel = raw.subarray(0, 4).toString('hex');
    const blk = newBlock(chain.nextBlockTime === null ? undefined : chain.nextBlockTime);
    chain.nextBlockTime = null;
    const txId = encode('QTX', crypto.randomBytes(32));
    let ok = true;
    let eventSel;
    let data;
    const read = (where, role, width) => raw.subarray(4 + where.at[role], 4 + where.at[role] + width);
    if (sel === wire.STAMP_UNTIL_SELECTOR) {
      const where = wire.LAYOUTS.stampUntil;
      const until = Number(read(where, 'until', 8).readBigUInt64BE(0));
      const anchored = Buffer.concat([read(where, 'hi', 16), read(where, 'lo', 16)]);
      const kind = read(where, 'kind', 8).readBigUInt64BE(0).toString();
      if (blk.time > until) ok = false;
      eventSel = wire.STAMPED_UNTIL_SELECTOR;
      data = wire.stampedEventData(from, anchored, kind, until);
    } else {
      const where = wire.LAYOUTS.stamp;
      const anchored = Buffer.concat([read(where, 'hi', 16), read(where, 'lo', 16)]);
      const kind = read(where, 'kind', 8).readBigUInt64BE(0).toString();
      eventSel = wire.STAMPED_SELECTOR;
      data = wire.stampedEventData(from, anchored, kind);
    }
    chain.txs.set(txId, { status: 'finalised', height: blk.height, block: blk.block, from, to, kind: 'call', raw: raw.toString('hex') });
    if (ok) chain.events.get(blk.height).push({ contract: to, selector: eventSel, data });
    return txId;
  }
  chain.submitCall = submitCall;
  return chain;
}

function client(chain, name, overrides) {
  const ov = overrides || {};
  const base = 'https://' + name + '.example';
  const c = {
    base,
    async nodeInfo() {
      if (ov.nodeInfo) return ov.nodeInfo(chain);
      return { chain_id: chain.chainId, genesis_hash: chain.genesis, head_height: chain.height };
    },
    async block(h) {
      if (ov.block) return ov.block(chain, h);
      const b = chain.blocks.get(h);
      return b ? Object.assign({}, b) : null;
    },
    async events(h) {
      if (ov.events) return ov.events(chain, h);
      return { events: (chain.events.get(h) || []).map((e) => Object.assign({}, e)) };
    },
    async transaction(id) {
      if (ov.transaction) return ov.transaction(chain, id);
      const t = chain.txs.get(id);
      return t ? Object.assign({}, t) : null;
    },
    async call(seed, index, to, argsHex) {
      const from = chain.core.address(seed, index);
      const txId = chain.submitCall(from, to, argsHex);
      return { outcome: { verdict: 'accepted', tx_id: txId } };
    },
  };
  return c;
}

const SEED = new Uint8Array(32).fill(7);

module.exports = { makeChain, client, encode, SEED, qstampRoot };
