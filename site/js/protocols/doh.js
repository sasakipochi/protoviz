// DoH: DNS の問い合わせを HTTPS (TLS 1.3 + HTTP/2) の中に入れて、途中から見えなくする
'use strict';
(() => {
const { pkt, h, ev, local, be, ip4, ascii, rand, tlv: T, dnsName } = PV;
const L = T.leaf;

const PC = '198.51.100.20', DNS53 = '198.51.100.53', DOH = '203.0.113.53', WEB = '203.0.113.80';
const HOST = 'dns.example.net', QNAME = 'www.example.com';
const CPORT = 50644;

/* ---------- DNS メッセージ ---------- */
function dnsMsg({ id, resp, padTo, edns = true }) {
  const q = [L('質問: 名前', dnsName(QNAME), `"${QNAME}"`, '長さ付きのラベルを並べた形 (3 www 7 example 3 com 0)'), L('質問: タイプ', be(1, 2), '1 (A: IPv4 アドレス)'), L('質問: クラス', be(1, 2), '1 (IN)')];
  const an = resp ? [L('回答: 名前', [0xc0, 0x0c], '→ 質問の名前 (圧縮ポインタ)', '先頭から 12 バイト目の名前をもう一度使う'), L('回答: タイプ', be(1, 2), '1 (A)'), L('回答: クラス', be(1, 2), '1 (IN)'),
    L('回答: TTL', be(300, 4), '300 秒', 'この答えを覚えておいてよい時間'), L('回答: データ長', be(4, 2), '4'), L('回答: アドレス', ip4(WEB), WEB, '答え')] : [];
  const head = [L('ID', be(id, 2), id ? '0x' + id.toString(16) : '0', id ? '問い合わせと答えを対応づける乱数' : 'DoH では 0 にする (同じ問い合わせが HTTP のキャッシュに載るように)'),
    L('フラグ', be(resp ? 0x8180 : 0x0100, 2), resp ? '0x8180 (応答, 再帰あり)' : '0x0100 (問い合わせ, 再帰してほしい)'),
    L('質問の数', be(1, 2), '1'), L('回答の数', be(resp ? 1 : 0, 2), resp ? '1' : '0'), L('権威の数', be(0, 2), '0'), L('追加の数', be(edns ? 1 : 0, 2), edns ? '1' : '0')];
  const base = [...head, ...q, ...an];
  if (!edns) return base;
  const baseLen = base.reduce((a, n) => a + n.bytes.length, 0) + 11 + (padTo ? 4 : 0);
  const pad = padTo ? Math.ceil(baseLen / padTo) * padTo - baseLen : 0;
  const optData = padTo ? [...be(12, 2), ...be(pad, 2), ...Array(pad).fill(0)] : [];
  return [...base,
    L('追加: OPT (EDNS)', [0, ...be(41, 2), ...be(1232, 2), 0, 0, 0, 0], 'タイプ 41, UDP サイズ 1232', 'DNS を拡張するための疑似レコード'),
    L('  データ長', be(optData.length, 2), `${optData.length}`),
    ...(padTo ? [L(`  パディング (オプション 12)`, optData, `00 × ${pad}`, `全体の長さを ${padTo} バイトの倍数にそろえ、長さから問い合わせの中身を推測されにくくする (RFC 8467)`)] : [])];
}
const lenOf = (nodes) => nodes.reduce((a, n) => a + T.enc(n).length, 0);
const emitAll = (p, nodes) => nodes.forEach((n) => T.emit(p, n));

/* ---------- TCP (シーケンス番号を追う) ---------- */
const seq = { c: 1000000, s: 3000000 };
function tcpPkt(fromClient, flags, summary, build, note) {
  const p = pkt(summary, { note });
  h.ipv4(p, fromClient ? { src: PC, dst: DOH, proto: 6, id: 0x4100 + seq.c % 200 } : { src: DOH, dst: PC, proto: 6, ttl: 55, id: 0x9100 + seq.s % 200 });
  const me = fromClient ? 'c' : 's', you = fromClient ? 's' : 'c';
  h.tcp(p, { sport: fromClient ? CPORT : 443, dport: fromClient ? 443 : CPORT, seq: seq[me], ack: flags.includes('ACK') ? seq[you] : 0, flags, sname: fromClient ? undefined : 'https', dname: fromClient ? 'https' : undefined });
  const start = p.layers.length;
  if (build) build(p);
  if (flags.includes('SYN')) seq[me] += 1;
  seq[me] += p.layers.slice(start).filter((l) => !l.decoded).reduce((a, l) => a + l.fields.reduce((b, f) => b + f.bytes.length, 0), 0);
  return p;
}

/* ---------- TLS ---------- */
const ext = (type, name, kids, desc) => T.node(`拡張: ${name}`, be(type, 2), 2, kids, { desc });
const record = (type, name, kids) => T.node(`TLS レコード: ${name}`, [type, 3, type === 22 && name === 'Handshake' && kids[0].head[0] === 1 ? 1 : 3], 2, kids, { desc: 'タイプ (1) + バージョン (2、互換のための固定値) + 長さ (2)' });
const encRecord = (seed, plainLen, what) => T.node('TLS レコード: Application Data', [23, 3, 3], 2, [L('暗号文', rand(seed, plainLen + 1), `(${plainLen + 1} バイト) ${what}`, '中身 + 本当のレコード種別 (1 バイト)。外から見るとすべて「Application Data」'), L('認証タグ', rand(seed + '-tag', 16), '(16 バイト)', 'AES-128-GCM の改ざん検知用')]);

const clientHello = () => record(22, 'Handshake', [T.node('ClientHello', [1], 3, [
  L('バージョン', [3, 3], '0x0303 (TLS 1.2 のふり)', '古い機器を混乱させないための固定値。本当のバージョンは supported_versions 拡張で伝える'),
  L('ランダム', rand('ch-random', 32), '(32 バイト)'),
  T.node('セッション ID', [], 1, [L('値', rand('ch-sid', 32), '(32 バイト)', 'TLS 1.3 では使わないが、互換のために乱数を入れる')]),
  T.node('暗号スイート', [], 2, [L('', [0x13, 0x01], 'TLS_AES_128_GCM_SHA256'), L('', [0x13, 0x02], 'TLS_AES_256_GCM_SHA384'), L('', [0x13, 0x03], 'TLS_CHACHA20_POLY1305_SHA256')]),
  T.node('圧縮方式', [], 1, [L('', [0], '0 (なし)')]),
  T.node('拡張', [], 2, [
    ext(0, 'server_name (SNI)', [T.node('名前リスト', [], 2, [T.node('ホスト名', [0], 2, [L('名前', ascii(HOST), `"${HOST}"`)])])], '接続したいサーバの名前。暗号化されていないので、途中から見える'),
    ext(10, 'supported_groups', [T.node('グループ', [], 2, [L('', [0, 0x1d], 'x25519'), L('', [0, 0x17], 'secp256r1')])]),
    ext(13, 'signature_algorithms', [T.node('アルゴリズム', [], 2, [L('', [4, 3], 'ecdsa_secp256r1_sha256'), L('', [8, 4], 'rsa_pss_rsae_sha256'), L('', [8, 7], 'ed25519')])]),
    ext(16, 'ALPN', [T.node('プロトコル', [], 2, [T.node('h2', [], 1, [L('名前', ascii('h2'), '"h2" (HTTP/2)')])])], 'TLS の上で何を話すか'),
    ext(43, 'supported_versions', [T.node('バージョン', [], 1, [L('', [3, 4], '0x0304 (TLS 1.3)')])]),
    ext(51, 'key_share', [T.node('鍵の一覧', [], 2, [T.node('x25519', [0, 0x1d], 2, [L('公開鍵', rand('ch-x25519', 32), '(32 バイト)', 'ECDHE の公開鍵。これで最初の 1 往復のうちに鍵が決まる')])])]),
  ]),
])]);
const serverHello = () => record(22, 'Handshake', [T.node('ServerHello', [2], 3, [
  L('バージョン', [3, 3], '0x0303 (TLS 1.2 のふり)'),
  L('ランダム', rand('sh-random', 32), '(32 バイト)'),
  T.node('セッション ID', [], 1, [L('値', rand('ch-sid', 32), '(32 バイト) クライアントの値をそのまま返す')]),
  L('暗号スイート', [0x13, 0x01], 'TLS_AES_128_GCM_SHA256', '選んだ 1 つ'),
  L('圧縮方式', [0], '0'),
  T.node('拡張', [], 2, [
    ext(43, 'supported_versions', [L('', [3, 4], '0x0304 (TLS 1.3)')]),
    ext(51, 'key_share', [T.node('x25519', [0, 0x1d], 2, [L('公開鍵', rand('sh-x25519', 32), '(32 バイト)', 'ここで両者の鍵がそろい、以降はすべて暗号化される')])]),
  ]),
])]);
const ccs = () => T.node('TLS レコード: ChangeCipherSpec', [20, 3, 3], 2, [L('値', [1], '1', 'TLS 1.3 では意味がない。古いミドルボックスを通すための飾り')]);

/* ---------- HTTP/2 ---------- */
const FT = { 0: 'DATA', 1: 'HEADERS', 4: 'SETTINGS' };
function frame(p, type, flags, stream, payloadLen, flagName) {
  return p.f('長さ', be(payloadLen, 3), `${payloadLen} バイト`, 'フレームのヘッダ (9 バイト) より後ろの長さ')
    .u8('タイプ', type, `${type} (${FT[type]})`)
    .u8('フラグ', flags, flagName || String(flags))
    .u32('ストリーム ID', stream, String(stream), stream ? '1 つの接続の中で、どの要求/応答か' : '0 = 接続全体の設定');
}
const hp = (name, bytes, value, desc) => L(name, bytes, value, desc);
const lit = (idxBytes, name, val, desc) => hp(name, [...idxBytes, val.length, ...ascii(val)], `${name}: ${val}`, desc || 'HPACK: 名前は静的テーブルの番号、値はそのままの文字列 (インデックスしないリテラル)');
const CT = 'application/dns-message';

const qDns = dnsMsg({ id: 0, padTo: 128 });
const rDns = dnsMsg({ id: 0, resp: true, padTo: 468 });
const reqHeaders = [hp(':method', [0x83], ':method: POST', 'HPACK: 静的テーブル 3 番をそのまま使う (1 バイト)'), hp(':scheme', [0x87], ':scheme: https', '静的テーブル 7 番'),
  lit([0x04], ':path', '/dns-query'), lit([0x01], ':authority', HOST), lit([0x0f, 0x04], 'accept', CT),
  lit([0x0f, 0x10], 'content-type', CT, 'DoH の目印。中身が DNS のメッセージそのもの (バイナリ) だということ'), lit([0x0f, 0x0d], 'content-length', String(lenOf(qDns)))];
const resHeaders = [hp(':status', [0x88], ':status: 200', '静的テーブル 8 番'), lit([0x0f, 0x10], 'content-type', CT),
  lit([0x0f, 0x0d], 'content-length', String(lenOf(rDns))), lit([0x0f, 0x09], 'cache-control', 'max-age=300', 'DNS の TTL に合わせたキャッシュ時間')];
const PREFACE = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
const cSettings = [L('SETTINGS_ENABLE_PUSH', [0, 2, 0, 0, 0, 0], '0 (サーバプッシュ不要)'), L('SETTINGS_INITIAL_WINDOW_SIZE', [0, 4, ...be(6291456, 4)], '6291456')];
const sSettings = [L('SETTINGS_MAX_CONCURRENT_STREAMS', [0, 3, ...be(100, 4)], '100')];
const h2Len = (parts) => parts.reduce((a, x) => a + 9 + lenOf(x), 0);
const reqH2Len = PREFACE.length + h2Len([cSettings, reqHeaders, qDns]);
const resH2Len = h2Len([sSettings, [], resHeaders, rDns]);

// サーバの暗号化されたハンドシェイク (中身は要約)
const encExt = T.node('EncryptedExtensions', [8], 3, [T.node('拡張', [], 2, [ext(16, 'ALPN', [T.node('プロトコル', [], 2, [T.node('h2', [], 1, [L('名前', ascii('h2'), '"h2"', 'HTTP/2 で話すことに決まった')])])])])]);
const certMsg = T.node('Certificate', [11], 3, [L('証明書チェーン', rand('cert', 820), '(820 バイト、要約) dns.example.net の証明書 + 中間 CA', '実際は数 KB になることが多く、複数の TCP セグメントに分かれる')]);
const certVerify = T.node('CertificateVerify', [15], 3, [L('署名方式', [4, 3], 'ecdsa_secp256r1_sha256'), T.node('署名', [], 2, [L('値', rand('cv', 71), '(71 バイト)', 'ここまでのやりとり全体への署名。証明書の秘密鍵を持っている証拠')])]);
const sFin = T.node('Finished', [20], 3, [L('verify_data', rand('sfin', 32), '(32 バイト)', 'ハンドシェイクが改ざんされていない確認')]);
const cFin = T.node('Finished', [20], 3, [L('verify_data', rand('cfin', 32), '(32 バイト)')]);
const sHsLen = lenOf([encExt, certMsg, certVerify, sFin]);

PV.register({
  id: 'doh', name: 'DoH', title: 'DNS を HTTPS で隠す', group: 'アプリケーション層', layerLabel: 'L7 · HTTPS (TCP 443)',
  overview: {
    full: 'DNS over HTTPS',
    description: '普通の DNS は暗号化されていないので、Wi-Fi やプロバイダなど通り道にいる人から「どのサイトを見ようとしているか」が丸見えです。DoH は DNS の問い合わせをそのまま HTTPS の中に入れて送ります。外からは普通の Web 通信と区別がつきません。ブラウザ (Firefox, Chrome) や OS (Windows, iOS, Android) が対応しています。',
    facts: [['層', 'アプリケーション層 (HTTPS の上)'], ['ポート', 'TCP 443 (HTTP/3 なら UDP 443)'], ['URL の例', `https://${HOST}/dns-query`], ['中身の形', 'application/dns-message (DNS のメッセージそのもの)'], ['似たもの', 'DoT (DNS over TLS, TCP 853)'], ['規格', 'RFC 8484']],
  },
  nodes: {
    pc: { label: 'ブラウザ', sub: PC, x: 100, y: 205, icon: 'pc' },
    ap: { label: '公衆 Wi-Fi', sub: '通り道で見ている人', x: 320, y: 205, icon: 'attacker' },
    dns53: { label: 'Wi-Fi の DNS', sub: DNS53, x: 320, y: 320, icon: 'server' },
    inet: { label: 'インターネット', x: 560, y: 205, icon: 'cloud' },
    doh: { label: 'DoH サーバ', sub: DOH, x: 830, y: 205, icon: 'server' },
  },
  links: [['pc', 'ap'], ['ap', 'dns53'], ['ap', 'inet'], ['inet', 'doh']],
  height: 400,
  lifelines: ['pc', 'ap', 'dns53', 'doh'],
  legend: [['gray', '処理・観測'], ['red', '普通の DNS (平文)'], ['amber', 'TCP / TLS ハンドシェイク'], ['blue', '暗号化された DNS']],
  steps: [
    {
      title: '普通の DNS は丸見え',
      desc: `比較のために、まず普通の DNS (UDP 53 番) で ${QNAME} を調べます。問い合わせも答えも暗号化されていません。`,
      detail: 'Wi-Fi の提供者や、同じ Wi-Fi で通信を覗いている人は、誰がいつどのサイトの名前を調べたかを全部見られます。答えを書き換えて、偽のサイトに誘導することもできます (DNS スプーフィング)。\n\nDNSSEC は答えの改ざんを検出できますが、中身を隠すことはしません。',
      facts: [['宛先', `${DNS53}:53 (UDP)`], ['見えるもの', '調べた名前、答えの IP アドレス'], ['書き換え', 'できてしまう']],
      events: [
        ev('pc', 'dns53', 'red', 'DNS 問い合わせ', (() => {
          const p = pkt(`DNS 問い合わせ: ${QNAME} の IPv4 アドレスは？`, { note: '中身がすべて平文。名前がそのまま読める。' });
          h.ipv4(p, { src: PC, dst: DNS53, proto: 17, id: 0x31a0 });
          h.udp(p, { sport: 53124, dport: 53, dname: 'domain' });
          p.layer('DNS');
          emitAll(p, dnsMsg({ id: 0x4c1d }));
          return p;
        })()),
        ev('dns53', 'pc', 'red', 'DNS 応答', (() => {
          const p = pkt(`DNS 応答: ${QNAME} は ${WEB}`);
          h.ipv4(p, { src: DNS53, dst: PC, proto: 17, id: 0x7712 });
          h.udp(p, { sport: 53, dport: 53124, sname: 'domain' });
          p.layer('DNS');
          emitAll(p, dnsMsg({ id: 0x4c1d, resp: true }));
          return p;
        })()),
        local('ap', '見えた: www.example.com', `${PC} が ${QNAME} を調べ、答えは ${WEB}。\n\n通り道にいればフィルタで止めることも、偽の答えを先に返すこともできる。`),
      ],
    },
    {
      title: 'DoH サーバに TCP でつなぐ',
      desc: `DoH では、あらかじめ設定した DoH サーバ (${HOST}) に、普通の HTTPS と同じく TCP の 443 番でつなぎます。`,
      detail: `DoH サーバ自身のアドレスは、設定に IP アドレスを書いておくか、最初の 1 回だけ普通の DNS で調べます (ブートストラップ)。ここでは ${DOH} が分かっているものとします。\n\nこの 3 ウェイハンドシェイクは普通の TCP なので、通り道からは「${DOH} の 443 番につないだ」ことは見えます。`,
      facts: [['宛先', `${DOH}:443 (TCP)`]],
      events: [
        ev('pc', 'doh', 'amber', 'SYN', tcpPkt(true, 'SYN', 'TCP SYN → 443')),
        ev('doh', 'pc', 'amber', 'SYN, ACK', tcpPkt(false, 'SYN,ACK', 'TCP SYN, ACK')),
        ev('pc', 'doh', 'amber', 'ACK', tcpPkt(true, 'ACK', 'TCP ACK (接続確立)')),
      ],
    },
    {
      title: 'TLS 1.3 のあいさつ (ClientHello)',
      desc: 'ブラウザが TLS の ClientHello を送ります。使える暗号、鍵交換の公開鍵、つなぎたいサーバ名 (SNI) が入っています。',
      detail: 'TLS 1.3 では、ClientHello にいきなり鍵交換の公開鍵 (key_share) を入れるので、1 往復で暗号化が始まります。ALPN 拡張の "h2" は「この上で HTTP/2 を話したい」という意味です。\n\nただし ClientHello 自体は暗号化されていません。SNI の dns.example.net は通り道から見えるので、「この人は DoH を使っている」ことは分かります。何を調べたかは分かりません。SNI まで隠す仕組みとして ECH (Encrypted Client Hello) があります。',
      facts: [['SNI', `${HOST} (見える)`], ['ALPN', 'h2'], ['鍵交換', 'x25519']],
      events: [
        ev('pc', 'doh', 'amber', 'ClientHello', tcpPkt(true, 'PSH,ACK', `TLS ClientHello (SNI: ${HOST})`, (p) => { p.layer('TLS'); T.emit(p, clientHello()); })),
        local('ap', '見えた: dns.example.net', `SNI から「${HOST} に HTTPS でつないだ」ことは分かる。中で何を調べるかは見えない。`),
      ],
    },
    {
      title: 'サーバの返事で暗号化が始まる',
      desc: 'サーバは ServerHello で鍵交換の相手側を返します。これで両者は同じ鍵を計算でき、その後ろの証明書などはもう暗号化されています。',
      detail: 'TLS 1.2 までは証明書が平文で流れていましたが、TLS 1.3 では ServerHello の直後から暗号化されます。外から見ると「Application Data」のレコードが 1 つ続いているだけです。\n\n中身は EncryptedExtensions (ALPN で h2 に決定)、Certificate (サーバの証明書)、CertificateVerify (証明書の秘密鍵を持っている証明)、Finished です。ブラウザは証明書が dns.example.net のものかを確かめます。これで、偽の DoH サーバに答えを書き換えられる心配がなくなります。',
      facts: [['暗号スイート', 'TLS_AES_128_GCM_SHA256'], ['暗号化されて見えないもの', '証明書、ALPN の結果']],
      events: [
        ev('doh', 'pc', 'amber', 'ServerHello + 暗号化', tcpPkt(false, 'PSH,ACK', 'TLS ServerHello + 暗号化されたハンドシェイク', (p) => {
          p.layer('TLS');
          [serverHello(), ccs(), encRecord('s-hs', sHsLen, '暗号化されたハンドシェイク')].forEach((n) => T.emit(p, n));
          p.layer('暗号の中身 (復号すると)', { decoded: true });
          [encExt, certMsg, certVerify, sFin].forEach((n) => T.emit(p, n));
        }, 'Application Data の中身は、鍵を持っているブラウザにしか読めない。下の 🔓 の層は復号した場合の中身。')),
      ],
    },
    {
      title: 'HTTP/2 で DNS を問い合わせる',
      desc: `ブラウザは TLS の Finished を返し、続けて HTTP/2 で POST /dns-query を送ります。本文は ${QNAME} を問い合わせる DNS メッセージそのものです。`,
      detail: 'DNS のメッセージは、手順 1 の UDP のものとほぼ同じバイト列です。違いは、ID を 0 にしていること (HTTP のキャッシュに載りやすくするため) と、EDNS のパディングで 128 バイトの倍数にそろえていることです。長さから問い合わせた名前を推測されにくくします。\n\nHTTP/2 のヘッダは HPACK で圧縮されています。:method: POST は静的テーブルの 3 番を指す 1 バイト (0x83) だけになります。GET で ?dns=<Base64URL> として送る方法もあり、そちらは HTTP のキャッシュと相性がよいです。',
      facts: [['HTTP', `POST https://${HOST}/dns-query`], ['content-type', CT], ['DNS メッセージ', `${lenOf(qDns)} バイト (パディング込み)`]],
      events: [
        ev('pc', 'doh', 'blue', 'POST /dns-query', tcpPkt(true, 'PSH,ACK', `HTTPS: POST /dns-query (${QNAME} を問い合わせ)`, (p) => {
          p.layer('TLS');
          [ccs(), encRecord('c-fin', lenOf([cFin]), 'Finished'), encRecord('c-req', reqH2Len, 'HTTP/2 の要求')].forEach((n) => T.emit(p, n));
          p.layer('TLS Finished (復号すると)', { decoded: true }); T.emit(p, cFin);
          p.layer('HTTP/2 接続のプレフェイス', { decoded: true }).str('プレフェイス', PREFACE, 'HTTP/2 を始める合図の決まった文字列');
          frame(p.layer('HTTP/2 SETTINGS フレーム', { decoded: true }), 4, 0, 0, lenOf(cSettings)); emitAll(p, cSettings);
          frame(p.layer('HTTP/2 HEADERS フレーム', { decoded: true }), 1, 4, 1, lenOf(reqHeaders), '0x04 (END_HEADERS)'); emitAll(p, reqHeaders);
          frame(p.layer('HTTP/2 DATA フレーム', { decoded: true }), 0, 1, 1, lenOf(qDns), '0x01 (END_STREAM)');
          p.layer('DNS メッセージ (DATA の中身)', { decoded: true }); emitAll(p, qDns);
        }, '外から見えるのは、TLS のレコードが 3 つと、その長さだけ。')),
        local('ap', '見えるのは長さだけ', `${DOH}:443 に ${reqH2Len + 17 + 5} バイトほどの暗号化データが流れた、ということしか分からない。パディングのおかげで、長さから名前も推測しにくい。`),
      ],
    },
    {
      title: '答えも HTTPS で返ってくる',
      desc: `DoH サーバは普通の DNS と同じように名前を解決し、答え (${WEB}) を DNS メッセージのまま HTTP/2 の応答に入れて返します。`,
      detail: 'DoH サーバはリゾルバ (フルサービスリゾルバ) として、ルート → .com → example.com の権威サーバに問い合わせて答えを得ます。この先の問い合わせは普通の DNS なので、DoH が守るのは「ブラウザから DoH サーバまで」の区間だけです。\n\n応答は 468 バイトの倍数にパディングされます。cache-control の max-age は DNS の TTL (300 秒) に合わせてあります。',
      facts: [[':status', '200'], ['答え', `${QNAME} → ${WEB} (TTL 300 秒)`], ['DNS メッセージ', `${lenOf(rDns)} バイト (パディング込み)`]],
      state: { pc: `${QNAME} = ${WEB}` },
      events: [
        ev('doh', 'pc', 'blue', '200 OK (答え)', tcpPkt(false, 'PSH,ACK', `HTTPS: 200 OK (${QNAME} は ${WEB})`, (p) => {
          p.layer('TLS'); T.emit(p, encRecord('s-res', resH2Len, 'HTTP/2 の応答'));
          frame(p.layer('HTTP/2 SETTINGS フレーム', { decoded: true }), 4, 0, 0, lenOf(sSettings)); emitAll(p, sSettings);
          frame(p.layer('HTTP/2 SETTINGS フレーム (ACK)', { decoded: true }), 4, 1, 0, 0, '0x01 (ACK: あなたの設定を受け取った)');
          frame(p.layer('HTTP/2 HEADERS フレーム', { decoded: true }), 1, 4, 1, lenOf(resHeaders), '0x04 (END_HEADERS)'); emitAll(p, resHeaders);
          frame(p.layer('HTTP/2 DATA フレーム', { decoded: true }), 0, 1, 1, lenOf(rDns), '0x01 (END_STREAM)');
          p.layer('DNS メッセージ (DATA の中身)', { decoded: true }); emitAll(p, rDns);
        })),
        local('pc', 'Web サーバへ', `${QNAME} = ${WEB} が分かったので、ブラウザは ${WEB} に接続する。DoH の TLS 接続は閉じずに残しておき、次の問い合わせにも使う。`),
      ],
    },
  ],
  outro: {
    title: 'DNS の中身はそのまま、運び方を HTTPS に',
    text: 'DoH は DNS のメッセージを 1 バイトも変えずに、HTTP/2 の本文として TLS の中で運びました。通り道からは「DoH サーバに HTTPS でつないだ」ことまでしか分からず、何を調べたかも、答えも見えず、書き換えもできません。\n\nその代わり、DoH サーバの運営者には全部見えます。誰を信頼するかを、Wi-Fi やプロバイダから DoH サーバの運営者に移し替えた、とも言えます。',
    points: [
      '会社のネットワークでは、DoH によって社内の DNS フィルタやログが素通りされる問題がある。Firefox は use-application-dns.net という名前が引けないと DoH を自動で切る (カナリアドメイン)',
      'DoT (DNS over TLS) は TCP 853 番の専用ポートを使う。中身は同じように隠せるが、ポート番号で DNS だと分かるので止められやすい',
      'DoQ (DNS over QUIC, RFC 9250) や、HTTP/3 の上の DoH も使われ始めている',
      'SNI まで隠すには ECH (Encrypted Client Hello) が必要',
    ],
  },
});
})();
