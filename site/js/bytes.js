// パケットを「フィールドの並び」として組み立て、本物のバイト列にするための道具。
// 長さ・チェックサムは done() の時点で実際のバイト列から計算する。
'use strict';
const PV = (window.PV = window.PV || {});
PV.protocols = [];
PV.register = (p) => PV.protocols.push(p);

/* ---------- 基本のエンコード ---------- */
const hex = (arr) => arr.map((b) => b.toString(16).padStart(2, '0')).join(' ');
const be = (n, size) => {
  const out = [];
  for (let i = size - 1; i >= 0; i--) out.push(Number((BigInt(n) >> BigInt(8 * i)) & 255n));
  return out;
};
const ascii = (s) => [...new TextEncoder().encode(s)];
const ip4 = (s) => s.split('.').map(Number);
function ip6(s) {
  let [head, tail] = s.includes('::') ? s.split('::') : [s, null];
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = tail === null ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  return groups.flatMap((g) => be(parseInt(g || '0', 16), 2));
}
const mac = (s) => s.split(':').map((x) => parseInt(x, 16));
function hashStr(s) {
  let h = 2166136261 >>> 0;
  for (const c of s) h = Math.imul(h ^ c.codePointAt(0), 16777619) >>> 0;
  return h || 1;
}
// 暗号文・乱数など「それらしいバイト列」を決定的に作る (seed が同じなら毎回同じ)
const rand = (seed, n) => {
  let x = hashStr(String(seed));
  const out = [];
  for (let i = 0; i < n; i++) {
    x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
    out.push(x & 255);
  }
  return out;
};
function inetSum(bytes) {
  let s = 0;
  for (let i = 0; i < bytes.length; i += 2) s += (bytes[i] << 8) + (bytes[i + 1] ?? 0);
  while (s > 0xffff) s = (s & 0xffff) + (s >>> 16);
  return ~s & 0xffff;
}
Object.assign(PV, { hex, be, ascii, ip4, ip6, mac, rand });

/* ---------- パケットビルダ ---------- */
class Pkt {
  constructor(summary, opts = {}) {
    this.summary = summary;
    this.note = opts.note; // インスペクタ上部に出す補足
    this.layers = [];
  }
  // decoded: 回線上のバイトではなく「復号・デコードすると中身はこう」という層
  layer(name, opts = {}) {
    this.cur = { name, fields: [], decoded: !!opts.decoded, meta: opts.meta || {}, note: opts.note };
    this.layers.push(this.cur);
    return this;
  }
  f(name, bytes, value, desc, opts = {}) {
    this.cur.fields.push({
      name, bytes: [...bytes], value: value ?? (bytes.length ? hex(bytes) : ''), desc,
      depth: opts.depth || 0, calc: opts.calc, pass: opts.pass || 1,
    });
    return this;
  }
  u8(n, v, val, d, o) { return this.f(n, be(v, 1), val ?? String(v), d, o); }
  u16(n, v, val, d, o) { return this.f(n, be(v, 2), val ?? String(v), d, o); }
  u32(n, v, val, d, o) { return this.f(n, be(v, 4), val ?? String(v), d, o); }
  str(n, s, d, o) { return this.f(n, ascii(s), JSON.stringify(s), d, o); }
  blob(n, seed, len, val, d, o) { return this.f(n, rand(seed, len), val ?? `(${len} バイト)`, d, o); }
  // 後で計算する長さ: 自分の層の先頭から (同じ種類の層の) 末尾まで
  lenField(n, size, d, { from = 'layer', adj = 0, unit = 1 } = {}) {
    return this.f(n, Array(size).fill(0), '', d, {
      calc: (c) => {
        const len = (from === 'layer' ? c.layerLen() : c.lenFrom()) + adj;
        return { bytes: be(len / unit, size), value: `${len / unit}` + (unit === 1 ? ' バイト' : '') };
      },
    });
  }
  done() {
    for (const pass of [1, 2]) {
      this.layers.forEach((L, li) => L.fields.forEach((fld) => {
        if (fld.calc && fld.pass === pass) {
          const r = fld.calc(this.ctx(li));
          fld.bytes = r.bytes; fld.value = r.value;
        }
      }));
    }
    return this;
  }
  ctx(li) {
    const self = this;
    const L = this.layers[li];
    const bytesOf = (i) => self.layers[i].fields.flatMap((f) => f.bytes);
    const from = (i) => {
      const out = [];
      for (let j = i; j < self.layers.length && self.layers[j].decoded === self.layers[i].decoded; j++) out.push(...bytesOf(j));
      return out;
    };
    return {
      layer: L, li,
      layerLen: () => bytesOf(li).length,
      lenFrom: () => from(li).length,
      bytesOf, from: () => from(li),
      // 直前の IP 層 (チェックサムの疑似ヘッダ用)
      ip: () => { for (let j = li - 1; j >= 0; j--) if (self.layers[j].meta.ip) return self.layers[j].meta; return null; },
    };
  }
  wire() { return this.layers.filter((l) => !l.decoded); }
}
PV.pkt = (summary, opts) => new Pkt(summary, opts);

/* ---------- よく使うヘッダ ---------- */
const ETYPE = { 0x0800: 'IPv4', 0x86dd: 'IPv6', 0x0806: 'ARP' };
const IPPROTO = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 50: 'ESP', 58: 'ICMPv6' };

function pseudoSum(c, proto) {
  const ip = c.ip();
  const data = c.from();
  if (!ip) return inetSum(data);
  const ph = ip.ip === 4
    ? [...ip4(ip.src), ...ip4(ip.dst), 0, proto, ...be(data.length, 2)]
    : [...ip6(ip.src), ...ip6(ip.dst), ...be(data.length, 4), 0, 0, 0, proto];
  return inetSum([...ph, ...data]);
}
const csumField = (proto) => ({
  pass: 2,
  calc: (c) => { const v = pseudoSum(c, proto) || 0xffff; return { bytes: be(v, 2), value: '0x' + v.toString(16).padStart(4, '0') + ' (正しい値)' }; },
});

PV.h = {
  eth(p, { src, dst, type, dstName, srcName }) {
    return p.layer('Ethernet', { meta: { basic: true } })
      .f('宛先 MAC', mac(dst), dst + (dstName ? ` (${dstName})` : ''), '次に受け取る機器の MAC アドレス。IP の宛先ではなく「この区間で渡す相手」')
      .f('送信元 MAC', mac(src), src + (srcName ? ` (${srcName})` : ''))
      .u16('EtherType', type, `0x${type.toString(16).padStart(4, '0')} (${ETYPE[type] || '?'})`, '中身のプロトコル');
  },
  ipv4(p, { src, dst, proto, ttl = 64, id = 0, df = true, tos = 0, name = 'IPv4' }) {
    return p.layer(name, { meta: { ip: 4, src, dst, basic: true } })
      .u8('バージョン / ヘッダ長', 0x45, '4 / 20 バイト', '上位4ビットが IP のバージョン、下位4ビットがヘッダ長 (4バイト単位)')
      .u8('DSCP / ECN', tos, String(tos), 'QoS のための優先度表示')
      .lenField('全長', 2, 'IP ヘッダを含むパケット全体の長さ', { from: 'rest' })
      .u16('識別子', id, String(id), '分割 (フラグメント) されたときに同じパケットだと分かるための番号')
      .u16('フラグ / オフセット', df ? 0x4000 : 0, df ? 'DF (分割禁止)' : '0', 'DF=1 なら途中で分割しない')
      .u8('TTL', ttl, String(ttl), 'ルータを1つ越えるたびに1減り、0 になると破棄される')
      .u8('プロトコル', proto, `${proto} (${IPPROTO[proto] || '?'})`, '中身が何か')
      .f('ヘッダチェックサム', [0, 0], '', 'IP ヘッダだけを対象にした検査用の値', {
        pass: 2, calc: (c) => { const v = inetSum(c.bytesOf(c.li)); return { bytes: be(v, 2), value: '0x' + v.toString(16).padStart(4, '0') + ' (正しい値)' }; },
      })
      .f('送信元 IP', ip4(src), src)
      .f('宛先 IP', ip4(dst), dst);
  },
  ipv6(p, { src, dst, next, hlim = 64, name = 'IPv6' }) {
    return p.layer(name, { meta: { ip: 6, src, dst, basic: true } })
      .u32('バージョン / クラス / フローラベル', 0x60000000, '6 / 0 / 0', '先頭4ビットが 6')
      .f('ペイロード長', [0, 0], '', 'IPv6 ヘッダ (40バイト固定) より後ろの長さ', {
        calc: (c) => { const n = c.lenFrom() - 40; return { bytes: be(n, 2), value: n + ' バイト' }; },
      })
      .u8('次ヘッダ', next, `${next} (${IPPROTO[next] || '?'})`, 'IPv4 の「プロトコル」にあたる')
      .u8('ホップリミット', hlim, String(hlim), 'IPv4 の TTL にあたる。NDP では 255 固定 (ルータを越えてきた偽物を弾くため)')
      .f('送信元 IP', ip6(src), src)
      .f('宛先 IP', ip6(dst), dst);
  },
  udp(p, { sport, dport, sname, dname }) {
    return p.layer('UDP', { meta: { basic: true } })
      .u16('送信元ポート', sport, String(sport) + (sname ? ` (${sname})` : ''))
      .u16('宛先ポート', dport, String(dport) + (dname ? ` (${dname})` : ''))
      .lenField('長さ', 2, 'UDP ヘッダ (8バイト) + データ', { from: 'rest' })
      .f('チェックサム', [0, 0], '', 'IP アドレスを含む疑似ヘッダとデータ全体から計算', csumField(17));
  },
  tcp(p, { sport, dport, seq, ack = 0, flags, win = 64240, sname, dname }) {
    const F = { FIN: 1, SYN: 2, RST: 4, PSH: 8, ACK: 16 };
    const fl = flags.split(',').reduce((a, k) => a | F[k.trim()], 0);
    return p.layer('TCP', { meta: { basic: true } })
      .u16('送信元ポート', sport, String(sport) + (sname ? ` (${sname})` : ''))
      .u16('宛先ポート', dport, String(dport) + (dname ? ` (${dname})` : ''))
      .u32('シーケンス番号', seq, String(seq), '自分が送るデータの何バイト目か')
      .u32('確認応答番号', ack, String(ack), '相手のデータを何バイト目まで受け取ったか')
      .u16('ヘッダ長 / フラグ', 0x5000 | fl, `20 バイト / ${flags}`, 'SYN=接続開始, ACK=確認応答, PSH=すぐ渡して, FIN=終了')
      .u16('ウィンドウ', win, String(win), 'まだ受け取れる量')
      .f('チェックサム', [0, 0], '', '疑似ヘッダ + TCP 全体', csumField(6))
      .u16('緊急ポインタ', 0, '0');
  },
  icmp6csum: () => csumField(58),
  icmp4csum: () => ({ pass: 2, calc: (c) => { const v = inetSum(c.from()); return { bytes: be(v, 2), value: '0x' + v.toString(16).padStart(4, '0') + ' (正しい値)' }; } }),
};

/* ---------- ASN.1 DER (Kerberos 用) ---------- */
function derLen(n) {
  if (n < 128) return [n];
  const b = [];
  while (n) { b.unshift(n & 255); n >>= 8; }
  return [0x80 | b.length, ...b];
}
function intBytes(v) {
  const b = [];
  let x = BigInt(v);
  do { b.unshift(Number(x & 255n)); x >>= 8n; } while (x > 0n);
  if (b[0] & 0x80) b.unshift(0);
  return b;
}
const D = {
  seq: (name, kids, desc) => ({ t: 'con', tag: 0x30, name, kids, desc }),
  app: (n, name, kids, desc) => ({ t: 'con', tag: 0x60 | n, name, kids, desc }),
  ctx: (n, name, child, desc) => ({ t: 'ctx', tag: 0xa0 | n, n, name, child, desc }),
  octDer: (name, child, desc) => ({ t: 'con', tag: 0x04, name, kids: [child], desc }),
  int: (v, value, desc) => ({ t: 'leaf', tag: 0x02, content: intBytes(v), value: value ?? String(v), desc }),
  gstr: (s, desc) => ({ t: 'leaf', tag: 0x1b, content: ascii(s), value: JSON.stringify(s), desc }),
  time: (s, value, desc) => ({ t: 'leaf', tag: 0x18, content: ascii(s), value: value ?? s, desc }),
  oct: (content, value, desc) => ({ t: 'leaf', tag: 0x04, content, value: value ?? `(${content.length} バイト)`, desc }),
  bits: (content, value, desc) => ({ t: 'leaf', tag: 0x03, content: [0, ...content], value, desc }),
};
D.content = (node) => {
  if (node.t === 'leaf') return node.content;
  if (node.t === 'ctx') return D.enc(node.child);
  return node.kids.flatMap(D.enc);
};
D.hdr = (node) => [node.tag, ...derLen(D.content(node).length)];
D.enc = (node) => [...D.hdr(node), ...D.content(node)];
// DER の木をフィールドとしてパケットに書き出す
D.emit = (p, node, depth = 0) => {
  if (node.t === 'ctx') {
    const ch = node.child;
    if (ch.t === 'leaf') return p.f(node.name, [...D.hdr(node), ...D.enc(ch)], ch.value, node.desc || ch.desc, { depth });
    p.f(node.name, [...D.hdr(node), ...D.hdr(ch)], ch.name || '', node.desc || ch.desc, { depth });
    ch.kids.forEach((k) => D.emit(p, k, depth + 1));
    return p;
  }
  if (node.t === 'con') {
    p.f(node.name, D.hdr(node), '', node.desc, { depth });
    node.kids.forEach((k) => D.emit(p, k, depth + 1));
    return p;
  }
  return p.f(node.name || '値', D.enc(node), node.value, node.desc, { depth });
};
PV.der = D;

/* ---------- イベント ---------- */
// ev: パケット1つの移動。to は配列でもよい (マルチキャスト)
PV.ev = (from, to, color, label, packet, opts = {}) => ({ kind: 'pkt', from, to, color, label, packet: packet && packet.done(), ...opts });
// local: ノード内での処理 (鍵の計算、経路選択など)
PV.local = (node, label, text, opts = {}) => ({ kind: 'local', from: node, to: node, color: 'gray', label, text, ...opts });
