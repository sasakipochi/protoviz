// IPsec: IKEv2 で鍵を決めて、ESP トンネルで拠点間をつなぐ
'use strict';
(() => {
const { pkt, h, ev, local, be, ip4, rand, ascii, hex } = PV;

const HA = '10.1.0.10', HB = '10.2.0.20';
const GA = '198.51.100.10', GB = '203.0.113.20';
const SPII = rand('ike-spii', 8), SPIR = rand('ike-spir', 8);
const SPI_AB = 0xc1a2b3c4; // B が受け取る SA (A→B) の SPI。B が決める
const SPI_BA = 0x8f3e2d1c; // A が受け取る SA (B→A) の SPI。A が決める
const PT = { 0: 'なし', 33: 'SA', 34: 'KE', 35: 'IDi', 36: 'IDr', 39: 'AUTH', 40: 'Nonce', 41: 'Notify', 44: 'TSi', 45: 'TSr', 46: 'SK (暗号化)' };
const XCHG = { 34: 'IKE_SA_INIT', 35: 'IKE_AUTH', 36: 'CREATE_CHILD_SA', 37: 'INFORMATIONAL' };

function ikeHdr(p, { resp, next, xchg, msgid, init }) {
  return p.layer('IKEv2 ヘッダ')
    .f('イニシエータ SPI', SPII, hex(SPII), '開始側が決めた 8 バイトの番号。この IKE SA を識別する')
    .f('レスポンダ SPI', init && !resp ? Array(8).fill(0) : SPIR, init && !resp ? '0 (まだ決まっていない)' : hex(SPIR), '応答側が決める番号。最初の要求ではまだ 0')
    .u8('次ペイロード', next, `${next} (${PT[next]})`, 'IKE はペイロードを数珠つなぎにする。各ペイロードが「次は何か」を持つ')
    .u8('バージョン', 0x20, '2.0')
    .u8('交換タイプ', xchg, `${xchg} (${XCHG[xchg]})`)
    .u8('フラグ', resp ? 0x20 : 0x08, resp ? 'R (応答)' : 'I (イニシエータからの要求)')
    .u32('メッセージ ID', msgid, String(msgid), '要求と応答の組を対応づける番号。再送の検出にも使う')
    .lenField('長さ', 4, 'IKE メッセージ全体の長さ', { from: 'rest' });
}
function payload(p, name, next, opts) {
  return p.layer(`ペイロード: ${name}`, opts)
    .u8('次ペイロード', next, `${next} (${PT[next]})`)
    .u8('クリティカル / 予約', 0, '0')
    .lenField('ペイロード長', 2, 'このペイロードの長さ');
}
function transform(p, last, type, typeName, id, idName, keyLen) {
  return p.u8(`変換: ${typeName}`, last ? 0 : 3, last ? '最後' : '続きあり', undefined, { depth: 1 })
    .u8('  予約', 0, '0', undefined, { depth: 2 })
    .u16('  変換の長さ', keyLen ? 12 : 8, keyLen ? '12' : '8', undefined, { depth: 2 })
    .u8('  種類', type, `${type} (${typeName})`, undefined, { depth: 2 })
    .u8('  予約', 0, '0', undefined, { depth: 2 })
    .u16('  ID', id, `${id} (${idName})`, undefined, { depth: 2 })
    .f('  属性: 鍵長', keyLen ? [0x80, 0x0e, ...be(keyLen, 2)] : [], keyLen ? `${keyLen} ビット` : '', undefined, { depth: 2 });
}
function saIke(p, next) {
  payload(p, 'SA (セキュリティアソシエーション)', next)
    .u8('プロポーザル: 最後か', 0, '最後', 'イニシエータは候補を複数並べられる。応答側はその中から1つ選んで返す')
    .u8('予約', 0, '0')
    .lenField('プロポーザル長', 2, undefined, { adj: -4 })
    .u8('プロポーザル番号', 1, '1')
    .u8('プロトコル', 1, '1 (IKE)')
    .u8('SPI サイズ', 0, '0')
    .u8('変換の数', 3, '3');
  transform(p, false, 1, '暗号', 20, 'AES-GCM 16バイト ICV', 256);
  transform(p, false, 2, '擬似乱数関数', 5, 'HMAC-SHA2-256');
  return transform(p, true, 4, '鍵交換 (DH)', 31, 'Curve25519');
}
function initMsg(resp) {
  const who = resp ? 'B' : 'A';
  const p = pkt(resp ? 'IKE_SA_INIT 応答: 候補から選んだ方式と、B の鍵交換の値' : 'IKE_SA_INIT 要求: 使える暗号方式の候補と、A の鍵交換の値', {
    note: 'このメッセージは暗号化されていない。DH 鍵交換の公開値だけを送り、秘密そのものは送らないので、盗聴されても鍵は分からない。',
  });
  h.ipv4(p, resp ? { src: GB, dst: GA, proto: 17, id: 0x5b21 } : { src: GA, dst: GB, proto: 17, id: 0x1a01 });
  h.udp(p, { sport: 500, dport: 500, sname: 'IKE', dname: 'IKE' });
  ikeHdr(p, { resp, next: 33, xchg: 34, msgid: 0, init: true });
  saIke(p, 34);
  payload(p, '鍵交換 (KE)', 40)
    .u16('DH グループ', 31, '31 (Curve25519)')
    .u16('予約', 0, '0')
    .blob('公開値', `ke-${who}`, 32, `(32 バイト) ${who} の公開鍵`, `${who} は秘密の乱数を作り、そこから計算した公開値だけを送る。両者の公開値と自分の秘密から、同じ共有秘密が計算できる`);
  payload(p, 'ノンス (Nonce)', 41)
    .blob('ノンス', `nonce-${who}`, 32, `(32 バイト) N${resp ? 'r' : 'i'}`, '使い捨ての乱数。鍵の材料に混ぜて、毎回違う鍵になるようにする');
  payload(p, 'Notify: NAT_DETECTION_SOURCE_IP', 41)
    .u8('プロトコル', 0, '0').u8('SPI サイズ', 0, '0')
    .u16('通知タイプ', 16388, '16388 (NAT_DETECTION_SOURCE_IP)')
    .blob('ハッシュ', `natd-src-${who}`, 20, 'SHA-1(SPI, 送信元 IP, ポート)', '受け取った側が同じ計算をして一致しなければ、途中で NAT がアドレスを書き換えたと分かる');
  payload(p, 'Notify: NAT_DETECTION_DESTINATION_IP', 0)
    .u8('プロトコル', 0, '0').u8('SPI サイズ', 0, '0')
    .u16('通知タイプ', 16389, '16389 (NAT_DETECTION_DESTINATION_IP)')
    .blob('ハッシュ', `natd-dst-${who}`, 20, 'SHA-1(SPI, 宛先 IP, ポート)');
  return p;
}

// IKE_AUTH の中身 (暗号化されている部分)
function authInner(p, resp) {
  const id = resp ? 'gw-b.example.net' : 'gw-a.example.net';
  payload(p, resp ? 'IDr (自分の名前)' : 'IDi (自分の名前)', 39, { decoded: true })
    .u8('ID の種類', 2, '2 (FQDN)').f('予約', [0, 0, 0], '0').str('ID', id, '相手に名乗る名前。証明書や事前共有鍵 (PSK) はこの名前に結びついている');
  payload(p, 'AUTH (認証)', 33, { decoded: true })
    .u8('認証方式', 14, '14 (デジタル署名)', 'ここでは証明書の秘密鍵で署名する方式。小規模なら 2 (事前共有鍵) もよく使う')
    .f('予約', [0, 0, 0], '0')
    .blob('署名', `auth-${resp}`, 64, '(64 バイト) Ed25519 署名', 'IKE_SA_INIT で自分が送ったメッセージ全体 + 相手のノンス + 自分の ID に署名する。これで「途中で書き換えられていない」「本当に gw-a/gw-b だ」が同時に確認できる');
  payload(p, `SA (ESP 用、${resp ? 'B' : 'A'} が受け取る側の SPI)`, 44, { decoded: true })
    .u8('プロポーザル: 最後か', 0, '最後').u8('予約', 0, '0')
    .lenField('プロポーザル長', 2, undefined, { adj: -4 })
    .u8('プロポーザル番号', 1, '1').u8('プロトコル', 3, '3 (ESP)').u8('SPI サイズ', 4, '4').u8('変換の数', 2, '2')
    .u32('SPI', resp ? SPI_AB : SPI_BA, '0x' + (resp ? SPI_AB : SPI_BA).toString(16), `${resp ? 'B' : 'A'} に届く ESP パケットに付けてほしい番号。受け取る側が決める`);
  transform(p, false, 1, '暗号', 20, 'AES-GCM 16バイト ICV', 256);
  transform(p, true, 5, '拡張シーケンス番号', 0, 'なし');
  const ts = (name, next, net) => payload(p, name, next, { decoded: true })
    .u8('セレクタの数', 1, '1').f('予約', [0, 0, 0], '0')
    .u8('種類', 7, '7 (IPv4 アドレス範囲)').u8('IP プロトコル', 0, '0 (すべて)').u16('セレクタ長', 16, '16')
    .u16('開始ポート', 0, '0').u16('終了ポート', 65535, '65535')
    .f('開始アドレス', ip4(`${net}.0`), `${net}.0`).f('終了アドレス', ip4(`${net}.255`), `${net}.255`, 'この範囲同士の通信を、このトンネルに通す');
  ts(resp ? 'TSi (A 側のネットワーク)' : 'TSi (自分側のネットワーク)', 45, '10.1.0');
  ts(resp ? 'TSr (B 側のネットワーク)' : 'TSr (相手側のネットワーク)', 0, '10.2.0');
}
function authMsg(resp) {
  const tmp = pkt('');
  authInner(tmp, resp);
  tmp.done();
  const plainLen = tmp.layers.reduce((a, L) => a + L.fields.reduce((b, f) => b + f.bytes.length, 0), 0) + 1; // + パディング長1バイト
  const p = pkt(resp ? 'IKE_AUTH 応答: B の名前・署名と、ESP の SA' : 'IKE_AUTH 要求: A の名前・署名と、作りたい ESP の SA', {
    note: 'IKE_SA_INIT で作った鍵 (SK_e) で中身が暗号化されている。下の 🔓 の層は、復号するとこう見えるという中身。',
  });
  h.ipv4(p, resp ? { src: GB, dst: GA, proto: 17, id: 0x5b22 } : { src: GA, dst: GB, proto: 17, id: 0x1a02 });
  h.udp(p, { sport: 500, dport: 500, sname: 'IKE', dname: 'IKE' });
  ikeHdr(p, { resp, next: 46, xchg: 35, msgid: 1 });
  payload(p, 'SK (暗号化されたペイロード)', resp ? 36 : 35)
    .blob('IV', `iv-auth-${resp}`, 8, '(8 バイト)', 'AES-GCM の初期化ベクトル。毎回変える')
    .blob('暗号文', `ct-auth-${resp}`, plainLen, `(${plainLen} バイト) 暗号化された ID・AUTH・SA・TS`, '中身は下の 🔓 の層')
    .blob('ICV (改ざん検知)', `icv-auth-${resp}`, 16, '(16 バイト)', '1ビットでも書き換えられていれば復号に失敗する');
  authInner(p, resp);
  p.layer('暗号文の末尾', { decoded: true }).u8('パディング長', 0, '0', 'AES-GCM はブロック境界にそろえる必要がないのでパディングなし');
  return p;
}

function icmp4(p, type, idv, seq) {
  return p.layer(type === 8 ? 'ICMP Echo Request' : 'ICMP Echo Reply')
    .u8('タイプ', type, type === 8 ? '8 (Echo Request)' : '0 (Echo Reply)')
    .u8('コード', 0, '0')
    .f('チェックサム', [0, 0], '', undefined, h.icmp4csum())
    .u16('識別子', idv, '0x' + idv.toString(16)).u16('シーケンス番号', seq, String(seq))
    .str('データ', 'abcdefghijklmnopqrstuvwabcdefghi');
}
function plainPing(reply) {
  const p = pkt(reply ? `ping 応答 ${HB} → ${HA} (拠点内は暗号化なし)` : `ping ${HA} → ${HB} (拠点内は暗号化なし)`);
  h.ipv4(p, reply ? { src: HB, dst: HA, proto: 1, id: 0x7e01 } : { src: HA, dst: HB, proto: 1, id: 0x31c5 });
  return icmp4(p, reply ? 0 : 8, 0x0b0c, 1);
}
function espPing(reply) {
  const inner = plainPing(reply).done();
  const innerLen = inner.layers.reduce((a, L) => a + L.fields.reduce((b, f) => b + f.bytes.length, 0), 0);
  const padLen = (4 - ((innerLen + 2) % 4)) % 4;
  const encLen = innerLen + padLen + 2;
  const spi = reply ? SPI_BA : SPI_AB;
  const p = pkt(reply ? `ESP: ゲートウェイ B → A (中身は ${HB} からの ping 応答)` : `ESP: ゲートウェイ A → B (中身は ${HA} からの ping)`, {
    note: 'インターネット上では、外側の IP (ゲートウェイ同士) と SPI・シーケンス番号しか見えない。元のパケットは宛先 IP も含めて丸ごと暗号化されている (トンネルモード)。',
  });
  h.ipv4(p, reply ? { src: GB, dst: GA, proto: 50, id: 0x5c10, name: '外側の IPv4' } : { src: GA, dst: GB, proto: 50, id: 0x1b10, name: '外側の IPv4' });
  p.layer('ESP')
    .u32('SPI', spi, '0x' + spi.toString(16), '受け取る側がどの SA (鍵) で復号するかを決める番号。IKE_AUTH で受け取る側が決めた値')
    .u32('シーケンス番号', 1, '1', 'SA ごとに 1 ずつ増える。同じパケットの再送り込み (リプレイ攻撃) を防ぐ')
    .blob('IV', `esp-iv-${reply}`, 8, '(8 バイト)')
    .blob('暗号文', `esp-ct-${reply}`, encLen, `(${encLen} バイト) 元の IP パケット + トレーラ`)
    .blob('ICV (改ざん検知)', `esp-icv-${reply}`, 16, '(16 バイト)', 'AES-GCM の認証タグ');
  inner.layers.forEach((L) => p.layers.push({ ...L, decoded: true, name: '元の ' + L.name, fields: L.fields.map((f) => ({ ...f, calc: undefined })) }));
  p.layer('ESP トレーラ', { decoded: true })
    .f('パディング', Array.from({ length: padLen }, (_, i) => i + 1), padLen ? hex(Array.from({ length: padLen }, (_, i) => i + 1)) : '(なし)', '長さを 4 バイト境界にそろえる')
    .u8('パディング長', padLen, String(padLen))
    .u8('次ヘッダ', 4, '4 (IPv4)', '中身が IP パケットまるごと = トンネルモード');
  return p;
}
function info(resp) {
  const p = pkt(resp ? 'INFORMATIONAL 応答 (空)' : 'INFORMATIONAL 要求 (空) = 生きてる？', { note: '中身が空の暗号化メッセージ。正しく復号・応答できること自体が「生きている」証拠になる (DPD: Dead Peer Detection)。' });
  h.ipv4(p, resp ? { src: GB, dst: GA, proto: 17, id: 0x5d01 } : { src: GA, dst: GB, proto: 17, id: 0x1c01 });
  h.udp(p, { sport: 500, dport: 500, sname: 'IKE', dname: 'IKE' });
  ikeHdr(p, { resp, next: 46, xchg: 37, msgid: 2 });
  payload(p, 'SK (暗号化されたペイロード)', 0)
    .blob('IV', `iv-info-${resp}`, 8, '(8 バイト)')
    .blob('暗号文', `ct-info-${resp}`, 1, '(1 バイト) パディング長のみ')
    .blob('ICV', `icv-info-${resp}`, 16, '(16 バイト)');
  return p;
}

PV.register({
  id: 'ipsec', name: 'IPsec (IKEv2 + ESP)', title: '拠点間 VPN', group: 'ネットワーク層', layerLabel: 'L3 · UDP 500/4500, IP プロトコル 50',
  overview: {
    full: 'IP Security — IKEv2 による鍵交換と ESP による暗号化',
    description: 'IPsec は IP パケットそのものを暗号化する仕組みで、拠点同士を結ぶ VPN によく使われます。まず IKEv2 で「お互いが本物か」を確かめつつ暗号鍵を決め (2往復)、そのあとは ESP というヘッダを付けて、元のパケットを丸ごと暗号化して送ります。',
    facts: [['鍵交換', 'IKEv2 (UDP 500, NAT 越えは 4500)'], ['データ', 'ESP (IP プロトコル番号 50)'], ['モード', 'トンネル (拠点間) / トランスポート'], ['認証', '証明書 or 事前共有鍵 (PSK)'], ['規格', 'RFC 7296 (IKEv2), RFC 4303 (ESP)']],
  },
  nodes: {
    ha: { label: 'PC-A', sub: HA, x: 80, y: 200, icon: 'pc' },
    ga: { label: 'VPN ゲートウェイ A', sub: GA, x: 290, y: 200, icon: 'router' },
    inet: { label: 'インターネット', x: 500, y: 200, icon: 'cloud' },
    gb: { label: 'VPN ゲートウェイ B', sub: GB, x: 710, y: 200, icon: 'router' },
    hb: { label: 'サーバ-B', sub: HB, x: 920, y: 200, icon: 'server' },
  },
  links: [['ha', 'ga'], ['ga', 'inet'], ['inet', 'gb'], ['gb', 'hb']],
  groups: [{ label: '拠点 A (10.1.0.0/24)', x: 20, y: 110, w: 380, h: 200 }, { label: '拠点 B (10.2.0.0/24)', x: 600, y: 110, w: 380, h: 200 }],
  lifelines: ['ha', 'ga', 'gb', 'hb'],
  legend: [['blue', '拠点内の通信 (平文)'], ['amber', 'IKE 要求'], ['violet', 'IKE 応答'], ['green', 'ESP (暗号化されたデータ)'], ['gray', '機器内の処理']],
  steps: [
    {
      title: 'トンネルが必要になる',
      desc: 'PC-A が拠点 B のサーバに ping を送ると、ゲートウェイ A は「これは暗号化して送るべき通信だ」と判断します。',
      detail: 'ゲートウェイには「どの通信を保護するか」というポリシー (SPD) が設定されています。ここでは「10.1.0.0/24 と 10.2.0.0/24 の間は IPsec で保護」です。\n\nところが、まだ相手と共有している鍵 (SA: セキュリティアソシエーション) がありません。そこでパケットを一時的に止めて、IKE による鍵交換を始めます。',
      facts: [['ポリシー (SPD)', '10.1.0.0/24 ⇄ 10.2.0.0/24 : 保護'], ['SA (SAD)', 'まだない']],
      events: [
        ev('ha', 'ga', 'blue', 'ping', plainPing(false)),
        local('ga', 'SPD に一致・SA なし', 'ポリシーデータベース (SPD) を引くと「保護する」に一致した。しかし使える SA がまだないので、IKE デーモン (strongSwan など) に鍵交換を依頼し、パケットは保留する。'),
      ],
    },
    {
      title: 'IKE_SA_INIT — 方式を決めて鍵を交換',
      desc: '1往復目。暗号方式の候補を出し合い、Diffie-Hellman 鍵交換の公開値とノンスを交換します。',
      detail: 'A は「AES-GCM-256 / SHA2-256 / Curve25519 でどう？」と候補を出し、B はその中から選んで返します。同時に DH 鍵交換の公開値を交換するので、この1往復が終わった時点で、盗聴者には分からない共通の秘密が両者にできます。\n\nNAT_DETECTION の通知は、途中に NAT があるかを調べるためのものです。NAT があると分かれば、以降は UDP 4500 番に切り替えて ESP も UDP に包みます (NAT トラバーサル)。',
      facts: [['暗号', 'AES-GCM 256 ビット'], ['PRF', 'HMAC-SHA2-256'], ['DH', 'Curve25519 (グループ 31)'], ['ポート', 'UDP 500 → 500']],
      events: [
        ev('ga', 'gb', 'amber', 'IKE_SA_INIT', initMsg(false)),
        ev('gb', 'ga', 'violet', 'IKE_SA_INIT', initMsg(true)),
      ],
    },
    {
      title: '鍵を計算する',
      desc: '両方のゲートウェイが、交換した値から同じ鍵の束を計算します。鍵そのものは一度も回線を流れません。',
      detail: 'DH の共有秘密とノンスから SKEYSEED を作り、そこから用途別の鍵を導出します。SK_d (この後の ESP 用の鍵の素)、SK_ei / SK_er (IKE メッセージの暗号化用、向きごと)、SK_pi / SK_pr (認証用) などです。',
      facts: [['SKEYSEED', 'prf(Ni | Nr, DH 共有秘密)'], ['導出', 'SK_d, SK_ei, SK_er, SK_pi, SK_pr']],
      state: { ga: 'IKE 鍵あり', gb: 'IKE 鍵あり' },
      events: [
        local('ga', '鍵を導出', '自分の DH 秘密と B の公開値から共有秘密を計算 → SKEYSEED = prf(Ni|Nr, 共有秘密) → SK_d, SK_ei, SK_er, SK_pi, SK_pr を導出。'),
        local('gb', '鍵を導出', 'B も自分の DH 秘密と A の公開値から、まったく同じ共有秘密と鍵の束を計算する。', { with: true }),
      ],
    },
    {
      title: 'IKE_AUTH — 相手が本物か確かめる',
      desc: '2往復目。ここからは暗号化されています。お互いに名乗り、署名で本人確認をし、データ用の SA (Child SA) を作ります。',
      detail: 'DH 鍵交換だけでは「誰と鍵を共有したか」が分かりません (途中で中間者がすり替わっているかもしれない)。そこで IKE_AUTH で、IKE_SA_INIT のやりとり全体に証明書の鍵で署名して送ります。相手の署名を確かめられれば、相手が本物で、しかも1往復目が改ざんされていないことが分かります。\n\n同じメッセージで、データ用の ESP の SA と、どの範囲の通信を流すか (トラフィックセレクタ: TSi / TSr) も決めます。',
      facts: [['A の ID', 'gw-a.example.net'], ['B の ID', 'gw-b.example.net'], ['トンネルに通す範囲', '10.1.0.0/24 ⇄ 10.2.0.0/24']],
      events: [
        ev('ga', 'gb', 'amber', 'IKE_AUTH', authMsg(false)),
        local('gb', '署名を検証', 'A の証明書を信頼できる CA で確認し、署名を検証する。TSi/TSr が自分のポリシーと合っているかも確認する。'),
        ev('gb', 'ga', 'violet', 'IKE_AUTH', authMsg(true)),
        local('ga', '署名を検証', 'B の署名を検証。これでお互いに本物だと確認できた。'),
      ],
    },
    {
      title: 'ESP の SA ができる',
      desc: '向きごとに1つずつ、計2つの SA ができました。トンネルの完成です。',
      detail: 'SA は一方通行です。A→B 用の SA は SPI 0xc1a2b3c4 (B が受け取るときに使う番号なので B が決めた値)、B→A 用は SPI 0x8f3e2d1c です。鍵は SK_d とノンスから計算され、カーネルの SA データベース (SAD) に登録されます。\n\nLinux なら `ip xfrm state` / `ip xfrm policy` で、この SA とポリシーを見ることができます。',
      facts: [['A → B', 'SPI 0xc1a2b3c4'], ['B → A', 'SPI 0x8f3e2d1c'], ['寿命', '例: 1時間 (期限前に作り直す)']],
      state: { ga: 'SA 2本 ✓', gb: 'SA 2本 ✓' },
      events: [
        local('ga', 'SA をカーネルに登録', '送信用 SA (SPI 0xc1a2b3c4) と受信用 SA (SPI 0x8f3e2d1c) をカーネルに登録。保留していた ping を送り出す。'),
        local('gb', 'SA をカーネルに登録', '受信用 SA (SPI 0xc1a2b3c4) と送信用 SA (SPI 0x8f3e2d1c) を登録。', { with: true }),
      ],
    },
    {
      title: 'ESP でデータを送る',
      desc: 'ゲートウェイ A は元のパケットを丸ごと暗号化し、外側に新しい IP ヘッダを付けて送ります。',
      detail: 'インターネット上を流れるのは「198.51.100.10 → 203.0.113.20 の ESP パケット」だけです。中の宛先 (10.2.0.20) も、ping であることも見えません。\n\nゲートウェイ B は SPI を見てどの SA の鍵で復号するか決め、ICV で改ざんがないことを確認し、取り出した元のパケットをサーバ-B に転送します。サーバ-B から見ると、普通の ping が届いただけです。',
      facts: [['外側', `${GA} → ${GB} (ESP)`], ['内側 (暗号化)', `${HA} → ${HB} (ICMP)`]],
      events: [
        ev('ha', 'ga', 'blue', 'ping', plainPing(false)),
        ev('ga', 'gb', 'green', 'ESP', espPing(false)),
        ev('gb', 'hb', 'blue', 'ping', plainPing(false)),
      ],
    },
    {
      title: '返事も ESP で',
      desc: '逆向きは、もう1本の SA (SPI 0x8f3e2d1c) で暗号化されて戻ります。',
      events: [
        ev('hb', 'gb', 'blue', 'ping 応答', plainPing(true)),
        ev('gb', 'ga', 'green', 'ESP', espPing(true)),
        ev('ga', 'ha', 'blue', 'ping 応答', plainPing(true)),
      ],
    },
    {
      title: '生きているか確認する',
      desc: 'しばらく通信がないと、IKE で「生きてる？」と確認します (DPD)。応答がなければ SA を消して作り直します。',
      detail: 'IKE SA と ESP の SA には寿命があり、切れる前に CREATE_CHILD_SA 交換で新しい鍵に入れ替えます (リキー)。こうして、同じ鍵を長く使いすぎないようにしています。',
      events: [
        ev('ga', 'gb', 'amber', 'INFORMATIONAL', info(false)),
        ev('gb', 'ga', 'violet', 'INFORMATIONAL', info(true)),
      ],
    },
  ],
  outro: {
    title: '2往復で鍵が決まり、あとは ESP で流すだけ',
    text: 'IKEv2 は IKE_SA_INIT (方式と DH 鍵交換) と IKE_AUTH (本人確認と ESP の SA 作成) の2往復で、拠点間の暗号化トンネルを作りました。そのあとのデータは、カーネルが ESP で暗号化・復号するだけです。',
    points: [
      'IKE (鍵交換) はユーザー空間のデーモン、ESP (データの暗号化) はカーネルが担当する、という分業になっている',
      'SA は片方向。SPI は「受け取る側」が決めた番号',
      '途中に NAT があると ESP (プロトコル 50) は通りにくいので、UDP 4500 番に包む (NAT-T)',
      '「つながらない」ときは、IKE の候補 (暗号方式) の不一致か、トラフィックセレクタ (TSi/TSr) の不一致が多い',
    ],
  },
});
})();
