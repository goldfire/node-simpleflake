var assert = require('assert');
var crypto = require('crypto');

try {
  var base58 = require('base58-native');
} catch (e) {
  base58 = null;
}

var opt = {
  epoch: Date.UTC(2000, 0, 1),
  timebits: 41,
};

var mask = (BigInt(2) ** BigInt(64)) - BigInt(1);

function simpleflake(ts, seq) {
  var timebits = opt.timebits;
  var seqbits = 64 - timebits;

  ts = BigInt((ts || Date.now()) - opt.epoch);
  assert(ts >= 0n, 'ts must be >= ' + opt.epoch);
  assert(ts.toString(2).length <= timebits, 'ts must be <= ' + timebits + ' bits');
  if (seq !== undefined) {
    seq = BigInt(seq);
    assert(seq.toString(2).length <= seqbits, 'seq must be <= ' + seqbits + ' bits');
  } else {
    seq = BigInt(`0x${crypto.randomBytes(Math.ceil(seqbits / 8)).toString('hex')}`);
  }

  var value = (ts << BigInt(seqbits)) | (seq & (mask >> BigInt(timebits)));
  var buf = Buffer.from(value.toString(16), 'hex');

  // Augment returned buffer with additional encoding option.
  buf.toString = toString;
  return buf;
}

function toString(enc) {
  if (enc === 'base58' && base58) {
    return base58.encode(this);
  } else if (enc === 'base10') {
    return BigInt(`0x${this.toString('hex')}`).toString(10);
  } else {
    return Buffer.prototype.toString.apply(this, arguments);
  }
}

function parse(buf, enc) {
  if (!Buffer.isBuffer(buf)) {
    if (enc === 'base58' && base58) {
      buf = Buffer.from(base58.decode(buf));
    } else if (enc === 'base10') {
      buf = Buffer.from(BigInt(buf).toString(16), 'hex');
    } else {
      buf = Buffer.from(buf, enc);
    }
  }
  var timebits = opt.timebits;
  var seqbits = 64 - timebits;
  var input = BigInt(`0x${buf.toString('hex')}`);
  return [
    Number((input >> BigInt(seqbits)) + BigInt(opt.epoch)),
    Number(input & (mask >> BigInt(timebits)))
  ];
}

module.exports = simpleflake;
module.exports.parse = parse;
module.exports.options = opt;
