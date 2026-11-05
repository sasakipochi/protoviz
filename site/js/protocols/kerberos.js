// Kerberos: パスワードを送らずにチケットでログインする
'use strict';
(() => {
const { pkt, h, ev, local, rand, ascii, der: D } = PV;

const C = '10.0.0.21', K = '10.0.0.5', W = '10.0.0.80';
const REALM = 'EXAMPLE.COM';
const ET = '18 (aes256-cts-hmac-sha1-96)';
const N = (name, node) => Object.assign(node, { name });
const int = (name, v, val, desc) => N(name, D.int(v, val, desc));

const pn = (type, names) => D.seq('PrincipalName', [
  D.ctx(0, 'name-type', D.int(type, `${type} (${type === 1 ? 'NT-PRINCIPAL: ユーザー' : 'NT-SRV-INST: サービス'})`)),
  D.ctx(1, 'name-string', D.seq('SEQUENCE OF', names.map((n) => N('名前', D.gstr(n))))),
], type === 1 ? undefined : undefined);
const encData = (seed, len, kvno, desc, val) => D.seq('EncryptedData', [
  D.ctx(0, 'etype', D.int(18, ET)),
  ...(kvno ? [D.ctx(1, 'kvno', D.int(kvno, `${kvno}`, '鍵のバージョン番号。パスワード変更のたびに増える'))] : []),
  D.ctx(2, 'cipher', D.oct(rand(seed, len), val || `(${len} バイト) 暗号文`, desc)),
]);
const ticket = (sname, seed, desc) => D.app(1, 'Ticket [APPLICATION 1]', [D.seq('Ticket', [
  D.ctx(0, 'tkt-vno', D.int(5)),
  D.ctx(1, 'realm', D.gstr(REALM)),
  D.ctx(2, 'sname', pn(2, sname)),
  D.ctx(3, 'enc-part', encData(seed, 236, 2, desc, `(236 バイト) ${sname.join('/')} の鍵で暗号化`)),
])], 'チケット。中身 (ユーザー名・セッション鍵・有効期限・PAC など) はサービス側の鍵で暗号化されていて、クライアントには読めない');
const reqBody = (sname, nonce, withCname) => D.seq('KDC-REQ-BODY', [
  D.ctx(0, 'kdc-options', D.bits([0x40, 0x81, 0x00, 0x10], 'forwardable, renewable, canonicalize, renewable-ok', '欲しいチケットの性質')),
  ...(withCname ? [D.ctx(1, 'cname', pn(1, ['alice']))] : []),
  D.ctx(2, 'realm', D.gstr(REALM)),
  D.ctx(3, 'sname', pn(2, sname)),
  D.ctx(5, 'till', D.time('20261106193000Z', '2026-11-06 19:30 UTC', 'この時刻まで有効なチケットが欲しい (実際は KDC のポリシーで決まる)')),
  D.ctx(7, 'nonce', D.int(nonce, String(nonce), '応答が今の要求に対するものだと確かめるための乱数')),
  D.ctx(8, 'etype', D.seq('SEQUENCE OF', [N('暗号方式', D.int(18, ET)), N('暗号方式', D.int(17, '17 (aes128-cts-hmac-sha1-96)'))]), 'クライアントが使える暗号方式'),
]);
const paData = (type, typeName, valueNode, desc) => D.seq('PA-DATA', [
  D.ctx(1, 'padata-type', D.int(type, `${type} (${typeName})`)),
  D.ctx(2, 'padata-value', valueNode),
], desc);

function kdcPacket(summary, node, toKdc, note) {
  const p = pkt(summary, { note });
  h.ipv4(p, toKdc ? { src: C, dst: K, proto: 17, id: 0x2201 } : { src: K, dst: C, proto: 17, id: 0x4401 });
  h.udp(p, toKdc ? { sport: 51034, dport: 88, dname: 'kerberos' } : { sport: 88, dport: 51034, sname: 'kerberos' });
  p.layer(summary.split(':')[0]);
  D.emit(p, node);
  return p;
}

const asReq1 = D.app(10, 'AS-REQ [APPLICATION 10]', [D.seq('KDC-REQ', [
  D.ctx(1, 'pvno', D.int(5, '5', 'Kerberos のバージョン')),
  D.ctx(2, 'msg-type', D.int(10, '10 (AS-REQ)')),
  D.ctx(4, 'req-body', reqBody(['krbtgt', REALM], 813275101, true)),
])]);
const krbError = D.app(30, 'KRB-ERROR [APPLICATION 30]', [D.seq('KRB-ERROR', [
  D.ctx(0, 'pvno', D.int(5)),
  D.ctx(1, 'msg-type', D.int(30, '30 (KRB-ERROR)')),
  D.ctx(4, 'stime', D.time('20261106003000Z', '2026-11-06 00:30:00 UTC', 'KDC の現在時刻')),
  D.ctx(5, 'susec', D.int(412577)),
  D.ctx(6, 'error-code', D.int(25, '25 (KDC_ERR_PREAUTH_REQUIRED)', '「事前認証が必要です」。エラーだが想定どおりの流れ')),
  D.ctx(9, 'realm', D.gstr(REALM)),
  D.ctx(10, 'sname', pn(2, ['krbtgt', REALM])),
  D.ctx(12, 'e-data', D.octDer('METHOD-DATA', D.seq('METHOD-DATA', [
    paData(19, 'PA-ETYPE-INFO2', D.octDer('ETYPE-INFO2', D.seq('ETYPE-INFO2', [D.seq('ETYPE-INFO2-ENTRY', [
      D.ctx(0, 'etype', D.int(18, ET)),
      D.ctx(1, 'salt', D.gstr('EXAMPLE.COMalice', 'パスワードから鍵を作るときに混ぜる値 (レルム名 + ユーザー名)')),
    ])]))),
    paData(2, 'PA-ENC-TIMESTAMP', D.oct([], '(空)', 'この方式で事前認証してね、という意味')),
  ])), 'どうやって事前認証すればよいかのヒント'),
])]);
const asReq2 = D.app(10, 'AS-REQ [APPLICATION 10]', [D.seq('KDC-REQ', [
  D.ctx(1, 'pvno', D.int(5)),
  D.ctx(2, 'msg-type', D.int(10, '10 (AS-REQ)')),
  D.ctx(3, 'padata', D.seq('SEQUENCE OF PA-DATA', [
    paData(2, 'PA-ENC-TIMESTAMP', D.octDer('EncryptedData', encData('ts', 56, 0, '現在時刻 (2026-11-06 00:30:01 UTC) を alice のパスワードから作った鍵で暗号化したもの', '(56 バイト) 現在時刻を alice の鍵で暗号化'))),
  ]), '事前認証データ。パスワードそのものではなく、パスワードから作った鍵で暗号化した時刻を送る'),
  D.ctx(4, 'req-body', reqBody(['krbtgt', REALM], 1694731162, true)),
])]);
const kdcRep = (app, type, sname, tktSeed, encSeed, encDesc, encVal) => D.app(app, `${type} [APPLICATION ${app}]`, [D.seq('KDC-REP', [
  D.ctx(0, 'pvno', D.int(5)),
  D.ctx(1, 'msg-type', D.int(app, `${app} (${type})`)),
  D.ctx(3, 'crealm', D.gstr(REALM)),
  D.ctx(4, 'cname', pn(1, ['alice'])),
  D.ctx(5, 'ticket', ticket(sname, tktSeed, sname[0] === 'krbtgt' ? 'TGT の中身は krbtgt (KDC 自身) の鍵で暗号化されている。alice にも読めない' : 'サービスチケットの中身は web サーバの鍵で暗号化されている')),
  D.ctx(6, 'enc-part', encData(encSeed, 172, app === 11 ? 1 : 0, encDesc, encVal), 'クライアント向けの部分。ここにセッション鍵が入っている'),
])]);
const asRep = kdcRep(11, 'AS-REP', ['krbtgt', REALM], 'tgt', 'asrep-enc', '中身: TGT 用セッション鍵、nonce (1694731162)、有効期限など。alice の鍵で暗号化', '(172 バイト) alice の鍵で暗号化');
const apReq = (tktSname, tktSeed, authSeed, authDesc, mutual) => D.app(14, 'AP-REQ [APPLICATION 14]', [D.seq('AP-REQ', [
  D.ctx(0, 'pvno', D.int(5)),
  D.ctx(1, 'msg-type', D.int(14, '14 (AP-REQ)')),
  D.ctx(2, 'ap-options', D.bits(mutual ? [0x20, 0, 0, 0] : [0, 0, 0, 0], mutual ? 'mutual-required' : 'なし', mutual ? 'サーバ側も本物であることを証明して (AP-REP を返して) ほしい' : undefined)),
  D.ctx(3, 'ticket', ticket(tktSname, tktSeed, '')),
  D.ctx(4, 'authenticator', encData(authSeed, 98, 0, authDesc, '(98 バイト) セッション鍵で暗号化された Authenticator'), 'オーセンティケータ。「alice です、今は○時○分です」をセッション鍵で暗号化したもの。チケットの盗用 (リプレイ) を防ぐ'),
])]);
const tgsReq = D.app(12, 'TGS-REQ [APPLICATION 12]', [D.seq('KDC-REQ', [
  D.ctx(1, 'pvno', D.int(5)),
  D.ctx(2, 'msg-type', D.int(12, '12 (TGS-REQ)')),
  D.ctx(3, 'padata', D.seq('SEQUENCE OF PA-DATA', [
    paData(1, 'PA-TGS-REQ', D.octDer('AP-REQ', apReq(['krbtgt', REALM], 'tgt', 'tgs-auth', '中身: cname=alice, ctime=00:30:05, req-body のチェックサム。TGT のセッション鍵で暗号化')), 'TGT とオーセンティケータ'),
  ])),
  D.ctx(4, 'req-body', reqBody(['HTTP', 'web.example.com'], 377215990, false)),
])]);
const tgsRep = kdcRep(13, 'TGS-REP', ['HTTP', 'web.example.com'], 'st', 'tgsrep-enc', '中身: サービス用セッション鍵、nonce (377215990)、有効期限など。TGT のセッション鍵で暗号化', '(172 バイト) TGT のセッション鍵で暗号化');
const apReqWeb = apReq(['HTTP', 'web.example.com'], 'st', 'web-auth', '中身: cname=alice, ctime=00:30:06, サブセッション鍵など。サービス用セッション鍵で暗号化', true);
const apRep = D.app(15, 'AP-REP [APPLICATION 15]', [D.seq('AP-REP', [
  D.ctx(0, 'pvno', D.int(5)),
  D.ctx(1, 'msg-type', D.int(15, '15 (AP-REP)')),
  D.ctx(2, 'enc-part', encData('aprep', 60, 0, '中身: alice が送った ctime と同じ時刻。サービス用セッション鍵で暗号化', '(60 バイト) セッション鍵で暗号化')),
])]);

// GSS-API (RFC 4121) の Kerberos トークンに包む
const OID_KRB5 = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
function gssToken(node, tokId) {
  const inner = [...OID_KRB5, ...tokId, ...D.enc(node)];
  return { hdr: D.hdr({ t: 'leaf', tag: 0x60, content: inner }), inner };
}
function httpWithToken(resp) {
  const node = resp ? apRep : apReqWeb;
  const tok = gssToken(node, resp ? [0x02, 0x00] : [0x01, 0x00]);
  const b64 = btoa(String.fromCharCode(...tok.hdr, ...tok.inner));
  const p = pkt(resp ? 'HTTP 200 OK + AP-REP (サーバも本物だと証明)' : 'HTTP GET + AP-REQ (サービスチケットを見せる)', {
    note: 'Kerberos のトークンは Base64 にして HTTP ヘッダに入れて送る (SPNEGO / Negotiate 認証)。実際のブラウザはさらに SPNEGO の構造で包むが、ここでは省略している。',
  });
  h.ipv4(p, resp ? { src: W, dst: C, proto: 6, id: 0x6602 } : { src: C, dst: W, proto: 6, id: 0x2302 });
  h.tcp(p, resp ? { sport: 80, dport: 50612, seq: 3001, ack: 1601, flags: 'PSH,ACK', sname: 'http' } : { sport: 50612, dport: 80, seq: 1, ack: 1, flags: 'PSH,ACK', dname: 'http' });
  const hdrName = resp ? 'WWW-Authenticate' : 'Authorization';
  p.layer('HTTP');
  if (resp) p.str('ステータス行', 'HTTP/1.1 200 OK\r\n');
  else p.str('リクエスト行', 'GET /reports/ HTTP/1.1\r\n').str('Host', 'Host: web.example.com\r\n');
  p.f(hdrName, ascii(`${hdrName}: Negotiate ${b64}\r\n`), `${hdrName}: Negotiate ${b64.slice(0, 24)}… (${b64.length} 文字)`, 'Base64 を戻すと下の 🔓 の GSS-API トークンになる');
  if (resp) p.str('Content-Type', 'Content-Type: text/html\r\n');
  p.str('ヘッダの終わり', '\r\n');
  p.layer('GSS-API トークン (Base64 をデコード)', { decoded: true })
    .f('[APPLICATION 0] ヘッダ', tok.hdr, '', 'GSS-API の共通の包み')
    .f('OID', OID_KRB5, '1.2.840.113554.1.2.2 (Kerberos v5)', 'このトークンは Kerberos 方式だという印')
    .f('TOK_ID', resp ? [0x02, 0x00] : [0x01, 0x00], resp ? '02 00 (AP-REP)' : '01 00 (AP-REQ)');
  p.layer(resp ? 'AP-REP' : 'AP-REQ', { decoded: true });
  D.emit(p, node);
  return p;
}

PV.register({
  id: 'kerberos', name: 'Kerberos', title: 'チケットでシングルサインオン', group: 'アプリケーション層', layerLabel: 'L7 · UDP/TCP 88',
  overview: {
    full: 'Kerberos v5 — 信頼できる第三者 (KDC) によるチケット認証',
    description: 'Kerberos は、パスワードをネットワークに流さずに本人確認をする仕組みです。最初に KDC から「チケットを発行してもらうためのチケット (TGT)」をもらい、以後はそれを使って各サービス用のチケットをもらいます。Active Directory のログインや、社内 Web のシングルサインオンの裏側で動いています。',
    facts: [['登場人物', 'クライアント, KDC (AS + TGS), サービス'], ['ポート', 'UDP/TCP 88 (大きいと TCP)'], ['形式', 'ASN.1 DER'], ['前提', '時計が合っていること (既定で ±5 分)'], ['規格', 'RFC 4120, RFC 4121 (GSS-API)']],
  },
  nodes: {
    client: { label: 'alice の PC', sub: C, x: 130, y: 220, icon: 'pc' },
    net: { label: '社内ネットワーク', x: 500, y: 250, icon: 'cloud' },
    kdc: { label: 'KDC', sub: 'dc.example.com', x: 500, y: 95, icon: 'key' },
    web: { label: '社内 Web', sub: 'web.example.com', x: 870, y: 220, icon: 'server' },
  },
  links: [['client', 'net'], ['net', 'kdc'], ['net', 'web']],
  groups: [{ label: 'レルム EXAMPLE.COM (AD ドメイン)', x: 20, y: 20, w: 960, h: 340 }],
  lifelines: ['client', 'kdc', 'web'],
  legend: [['gray', '機器内の処理'], ['amber', 'KDC への要求'], ['violet', 'KDC からの応答'], ['red', 'エラー'], ['blue', 'サービスとの通信']],
  steps: [
    {
      title: '準備: 鍵はどこにあるか',
      desc: 'KDC は全員の「パスワードから作った鍵」を持っています。サービスは自分の鍵 (keytab) を持っています。',
      detail: 'Kerberos の前提はこれだけです。ユーザーとサービスは、それぞれ自分の鍵を KDC とだけ共有している。KDC は「krbtgt」という自分自身の鍵も持っています。\n\nalice がログイン画面でパスワードを入力すると、PC はパスワード・ソルト (レルム名 + ユーザー名) から同じ鍵を計算します。パスワードそのものはどこにも送りません。',
      facts: [['alice の鍵', 'PBKDF2(パスワード, "EXAMPLE.COMalice")'], ['web の鍵', 'keytab に保存 (HTTP/web.example.com)'], ['krbtgt の鍵', 'KDC だけが知っている']],
      state: { client: '🔑 alice', kdc: '🔑 全員分', web: '🔑 web (keytab)' },
      events: [
        local('client', 'パスワード → 鍵', 'alice が入力したパスワードから、AES-256 の鍵を作る (string-to-key)。\n\n鍵 = PBKDF2-HMAC-SHA1(パスワード, ソルト "EXAMPLE.COMalice", 4096 回) をもとにした値。'),
      ],
    },
    {
      title: 'AS-REQ — TGT をください (1回目)',
      desc: 'PC は KDC の認証サービス (AS) に「alice です。TGT をください」と頼みます。最初は事前認証なしで送るのが一般的です。',
      detail: 'KDC は「事前認証が必要です」というエラー (PREAUTH_REQUIRED) と一緒に、鍵を作るためのソルトや暗号方式を教えてくれます。エラーですが、これは正常な流れです。\n\nもし事前認証なしでチケットを出してしまうと、誰でも alice 宛ての応答を手に入れて、オフラインでパスワードを総当たりできてしまいます (AS-REP Roasting)。',
      events: [
        ev('client', 'kdc', 'amber', 'AS-REQ', kdcPacket('AS-REQ: TGT をください (事前認証なし)', asReq1, true)),
        ev('kdc', 'client', 'red', 'KRB-ERROR', kdcPacket('KRB-ERROR: 事前認証が必要です', krbError, false, 'エラーコード 25 (PREAUTH_REQUIRED)。e-data に「ソルトは EXAMPLE.COMalice、方式は暗号化タイムスタンプで」というヒントが入っている。')),
      ],
    },
    {
      title: 'AS-REQ / AS-REP — TGT をもらう',
      desc: '今度は「現在時刻を自分の鍵で暗号化したもの」を付けて頼みます。KDC が復号できれば、alice 本人だと分かります。',
      detail: 'KDC は保存している alice の鍵で時刻を復号し、5分以内のずれなら本人と認めます。応答の AS-REP には2つのものが入っています。\n\n1つは TGT (チケットを発行してもらうためのチケット)。中身は KDC 自身の鍵で暗号化されていて、alice にも読めません。もう1つは alice の鍵で暗号化された部分で、ここに「TGT と一緒に使うセッション鍵」が入っています。alice は自分の鍵で復号して、セッション鍵を取り出します。',
      facts: [['TGT の暗号化', 'krbtgt の鍵 (KDC だけが読める)'], ['enc-part の暗号化', 'alice の鍵'], ['TGT の寿命', '例: 10 時間']],
      state: { client: '🎫 TGT', kdc: '✓ alice を確認' },
      events: [
        ev('client', 'kdc', 'amber', 'AS-REQ', kdcPacket('AS-REQ: TGT をください (暗号化タイムスタンプ付き)', asReq2, true)),
        local('kdc', '時刻を復号して確認', 'alice の鍵で PA-ENC-TIMESTAMP を復号 → 2026-11-06 00:30:01 UTC。KDC の時計との差は5分以内なので、alice 本人と判断する。\n\nTGT 用のセッション鍵を新しく作り、TGT (krbtgt の鍵で暗号化) と enc-part (alice の鍵で暗号化) の両方に入れる。'),
        ev('kdc', 'client', 'violet', 'AS-REP', kdcPacket('AS-REP: TGT と、TGT 用セッション鍵', asRep, false, 'ticket 部分は KDC の鍵で、enc-part は alice の鍵で暗号化されている。')),
        local('client', 'enc-part を復号', 'alice の鍵で enc-part を復号し、TGT 用セッション鍵を取り出す。nonce が自分の送った値と一致することも確認。\n\nTGT とセッション鍵を資格情報キャッシュ (klist で見える) に保存。この後パスワードから作った鍵は不要になる。'),
      ],
    },
    {
      title: 'TGS-REQ / TGS-REP — サービス用のチケットをもらう',
      desc: '社内 Web を開こうとすると、PC は TGT を見せて「HTTP/web.example.com 用のチケットをください」と頼みます。',
      detail: 'TGS-REQ には TGT と、オーセンティケータ (「alice です、今は○時○分」を TGT のセッション鍵で暗号化したもの) を付けます。KDC は自分の鍵で TGT を開けてセッション鍵を取り出し、それでオーセンティケータを復号して照合します。\n\n応答のサービスチケットは web サーバの鍵で暗号化されています。alice には中身が読めず、web サーバにだけ読めます。',
      facts: [['サービス名 (SPN)', 'HTTP/web.example.com'], ['チケットの暗号化', 'web サーバの鍵'], ['enc-part の暗号化', 'TGT のセッション鍵']],
      state: { client: '🎫 TGT + 🎫 HTTP/web' },
      events: [
        ev('client', 'kdc', 'amber', 'TGS-REQ', kdcPacket('TGS-REQ: HTTP/web.example.com 用のチケットをください', tgsReq, true, 'padata の中に AP-REQ (TGT + オーセンティケータ) が入っている。パスワードもユーザーの鍵も使っていない。')),
        ev('kdc', 'client', 'violet', 'TGS-REP', kdcPacket('TGS-REP: サービスチケットと、サービス用セッション鍵', tgsRep, false)),
      ],
    },
    {
      title: 'AP-REQ — サービスにチケットを見せる',
      desc: 'PC は Web サーバに、サービスチケットとオーセンティケータを HTTP ヘッダに入れて送ります。',
      detail: 'Web サーバは keytab にある自分の鍵でチケットを復号し、中にあるセッション鍵と「このチケットは alice のもの」という情報を取り出します。そのセッション鍵でオーセンティケータを復号し、名前と時刻が合っていれば alice と認めます。\n\nこの間、Web サーバは KDC に問い合わせていません。チケットを開けられること自体が、KDC が発行した証拠だからです。',
      state: { web: '✓ alice としてログイン' },
      events: [
        ev('client', 'web', 'blue', 'GET + AP-REQ', httpWithToken(false)),
        local('web', 'チケットを復号', 'keytab の鍵でチケットを復号 → cname=alice、セッション鍵、有効期限、PAC (所属グループなど) を取り出す。\n\nセッション鍵でオーセンティケータを復号 → cname=alice、時刻のずれ5分以内、同じオーセンティケータを以前に受け取っていない (リプレイでない) ことを確認。'),
        ev('web', 'client', 'blue', '200 + AP-REP', httpWithToken(true)),
        local('client', 'サーバを確認', 'AP-REP をセッション鍵で復号でき、中の時刻が自分の送ったものと一致した。つまり相手も本物の web.example.com (正しい鍵を持っている) と分かった (相互認証)。'),
      ],
    },
  ],
  outro: {
    title: 'パスワードは一度もネットワークを流れなかった',
    text: 'alice は最初に一度だけ TGT をもらい、あとは TGT を見せてサービスごとのチケットをもらいます。サービスはチケットを自分の鍵で開けるだけで、KDC に問い合わせる必要がありません。これがシングルサインオンの仕組みです。',
    points: [
      '時計がずれると失敗する (KRB_AP_ERR_SKEW)。NTP は必須',
      'サービスは名前 (SPN) で指定する。IP アドレスでアクセスすると Kerberos が使えず NTLM に落ちるのはこのため',
      'TGT を盗まれると、有効期限まではなりすませる (Pass-the-Ticket)',
      'サービスチケットはサービスの鍵で暗号化されているので、弱いパスワードのサービスアカウントは総当たりされうる (Kerberoasting)',
    ],
  },
});
})();
