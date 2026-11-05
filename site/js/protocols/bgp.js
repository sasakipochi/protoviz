// BGP: AS 同士が経路を教え合い、インターネットの道順ができる
'use strict';
(() => {
const { pkt, h, ev, local, be, ip4 } = PV;

const R = {
  r1: { ip: { r2: '192.0.2.1' }, id: '192.0.2.1', as: 64500 },
  r2: { ip: { r1: '192.0.2.2', r3: '192.0.2.5' }, id: '192.0.2.2', as: 64510 },
  r3: { ip: { r2: '192.0.2.6' }, id: '192.0.2.6', as: 64520 },
};
const PFX = '203.0.113.0/24', SRV = '203.0.113.10', USER = '198.51.100.25';
const MSG = { 1: 'OPEN', 2: 'UPDATE', 3: 'NOTIFICATION', 4: 'KEEPALIVE' };

// TCP のシーケンス番号をセッションごとに追跡する
const tcpState = {};
const sess = (a, b) => (tcpState[[a, b].sort().join('-')] ||= { [a]: 0, [b]: 0 });
const PORT = { r1: 179, r2: 179, r3: 179 };
const ephem = { 'r1-r2': 50123, 'r2-r3': 41780 };
Object.assign(sess('r2', 'r3'), { r2: 2210004001, r3: 977120221 }); // R2-R3 は確立済みのセッション

function bgpHdr(p, type, label) {
  return p.layer(`BGP ${label || MSG[type]}`)
    .f('マーカー', Array(16).fill(0xff), 'ff × 16', '昔の名残。今は常に全部 ff')
    .lenField('長さ', 2, 'この BGP メッセージ全体の長さ (19〜4096)')
    .u8('タイプ', type, `${type} (${MSG[type]})`);
}
// from が TCP の接続を開始した側なら送信元ポートは一時ポート
function bgpPkt(from, to, summary, build, note) {
  const tmp = pkt('');
  build(tmp);
  tmp.done();
  const len = tmp.layers.reduce((a, L) => a + L.fields.reduce((b, f) => b + f.bytes.length, 0), 0);
  const s = sess(from, to);
  const key = [from, to].sort().join('-');
  const initiator = key.split('-')[0];
  const p = pkt(summary, { note });
  h.ipv4(p, { src: R[from].ip[to], dst: R[to].ip[from], proto: 6, ttl: 1, tos: 0xc0, id: (s[from] & 0xffff) });
  h.tcp(p, {
    sport: from === initiator ? ephem[key] : 179, dport: to === initiator ? ephem[key] : 179,
    seq: s[from], ack: s[to], flags: 'PSH,ACK', sname: from === initiator ? undefined : 'bgp', dname: to === initiator ? undefined : 'bgp',
  });
  build(p);
  s[from] += len;
  return p;
}
function tcpCtl(from, to, flags, isn) {
  const s = sess(from, to);
  const key = [from, to].sort().join('-');
  const initiator = key.split('-')[0];
  if (flags.includes('SYN')) s[from] = isn;
  const p = pkt(`TCP ${flags} (${from === initiator ? '→ ポート 179' : 'ポート 179 から'})`);
  h.ipv4(p, { src: R[from].ip[to], dst: R[to].ip[from], proto: 6, ttl: 1, tos: 0xc0, id: 1 });
  h.tcp(p, {
    sport: from === initiator ? ephem[key] : 179, dport: to === initiator ? ephem[key] : 179,
    seq: s[from], ack: flags.includes('ACK') ? s[to] : 0, flags, sname: from === initiator ? undefined : 'bgp', dname: to === initiator ? undefined : 'bgp',
  });
  if (flags.includes('SYN')) s[from] += 1;
  return p;
}

const open = (from, to) => bgpPkt(from, to, `OPEN: AS${R[from].as} です。ホールドタイムは 90 秒で`, (p) => {
  bgpHdr(p, 1)
    .u8('バージョン', 4, '4')
    .u16('自分の AS 番号', R[from].as, String(R[from].as), '2 バイト欄。65535 を超える AS 番号のときは 23456 (AS_TRANS) を入れて、本当の値は 4 バイト AS ケーパビリティで伝える')
    .u16('ホールドタイム', 90, '90 秒', 'この時間なにも届かなければ相手が死んだとみなす。両者の小さい方が使われる')
    .f('BGP 識別子', ip4(R[from].id), R[from].id, 'ルータ ID。AS 内でルータを一意に区別する 32 ビットの値')
    .lenField('オプション長', 1, undefined, { adj: -29 })
    .u8('オプション: ケーパビリティ', 2, '2 (Capabilities)', '「自分はこの機能に対応している」の一覧')
    .lenField('  長さ', 1, undefined, { adj: -31 })
    .u8('ケーパビリティ: マルチプロトコル', 1, '1 (MP-BGP)', 'どのアドレスファミリの経路を交換するか', { depth: 1 })
    .u8('  長さ', 4, '4', undefined, { depth: 2 })
    .u16('  AFI', 1, '1 (IPv4)', undefined, { depth: 2 }).u8('  予約', 0, '0', undefined, { depth: 2 }).u8('  SAFI', 1, '1 (ユニキャスト)', undefined, { depth: 2 })
    .u8('ケーパビリティ: ルートリフレッシュ', 2, '2 (Route Refresh)', 'セッションを張り直さずに「経路を全部送り直して」と頼める', { depth: 1 })
    .u8('  長さ', 0, '0', undefined, { depth: 2 })
    .u8('ケーパビリティ: 4 バイト AS', 65, '65 (4-octet AS)', '4 バイトの AS 番号に対応している', { depth: 1 })
    .u8('  長さ', 4, '4', undefined, { depth: 2 })
    .u32('  AS 番号', R[from].as, String(R[from].as), undefined, { depth: 2 });
}, from === 'r1' ? 'eBGP では IP の TTL が 1。隣のルータにしか届かないようにしている (直結が前提)。' : undefined);
const keepalive = (from, to) => bgpPkt(from, to, 'KEEPALIVE: 生きています', (p) => bgpHdr(p, 4), 'ヘッダだけの 19 バイト。OPEN への返事であり、その後は定期的な生存通知になる。');

function update(from, to, { withdraw, asPath, nh }) {
  return bgpPkt(from, to, withdraw ? `UPDATE: ${PFX} を取り下げます` : `UPDATE: ${PFX} へは AS_PATH [${asPath.join(' ')}] で行けます`, (p) => {
    bgpHdr(p, 2);
    const pfx = [24, 203, 0, 113];
    if (withdraw) {
      p.u16('取り下げ経路の長さ', 4, '4 バイト')
        .u8('取り下げ: プレフィックス長', 24, '/24', 'この経路はもう使えない', { depth: 1 })
        .f('  プレフィックス', pfx.slice(1), '203.0.113', '/24 なので上位 3 バイトだけ書く', { depth: 1 })
        .u16('パス属性の長さ', 0, '0', '取り下げだけなので属性なし');
      return;
    }
    const attrLen = 4 + (3 + 2 + 4 * asPath.length) + 7;
    p.u16('取り下げ経路の長さ', 0, '0')
      .u16('パス属性の長さ', attrLen, `${attrLen} バイト`)
      .u8('属性: ORIGIN', 0x40, 'フラグ 0x40 (Well-known, 転送する)', 'この経路がどこから来たか', { depth: 1 })
      .u8('  タイプ', 1, '1 (ORIGIN)', undefined, { depth: 2 }).u8('  長さ', 1, '1', undefined, { depth: 2 })
      .u8('  値', 0, '0 (IGP)', 'AS 内のネットワークを network 文で広告した、の意味', { depth: 2 })
      .u8('属性: AS_PATH', 0x40, 'フラグ 0x40', '経路が通ってきた AS の列。ループ防止と経路選択に使う', { depth: 1 })
      .u8('  タイプ', 2, '2 (AS_PATH)', undefined, { depth: 2 }).u8('  長さ', 2 + 4 * asPath.length, String(2 + 4 * asPath.length), undefined, { depth: 2 })
      .u8('  セグメント種別', 2, '2 (AS_SEQUENCE)', '順序つきの AS の並び', { depth: 2 })
      .u8('  AS の数', asPath.length, String(asPath.length), undefined, { depth: 2 })
      .f('  AS 番号', asPath.flatMap((a) => be(a, 4)), asPath.join(' '), '左が一番最近通った AS。広告するたびに自分の AS を先頭に足す', { depth: 2 })
      .u8('属性: NEXT_HOP', 0x40, 'フラグ 0x40', undefined, { depth: 1 })
      .u8('  タイプ', 3, '3 (NEXT_HOP)', undefined, { depth: 2 }).u8('  長さ', 4, '4', undefined, { depth: 2 })
      .f('  次の宛先', ip4(nh), nh, 'この経路宛てのパケットはこのアドレスに渡して、の意味。eBGP では広告した自分のアドレス', { depth: 2 })
      .u8('NLRI: プレフィックス長', 24, '/24', '到達できるネットワーク')
      .f('  プレフィックス', pfx.slice(1), '203.0.113', '/24 なので上位 3 バイトだけ書く', { depth: 1 });
  }, withdraw ? undefined : 'UPDATE は「パス属性 (共通の性質)」と「NLRI (その属性を持つプレフィックスの一覧)」の組。同じ属性なら何百ものプレフィックスを1通にまとめられる。');
}
function userSyn() {
  const p = pkt(`TCP SYN ${USER} → ${SRV}:443`, { note: 'BGP 自体はパケットを運ばない。BGP で作った経路表 (FIB) に従って、各ルータがパケットを転送する。' });
  h.ipv4(p, { src: USER, dst: SRV, proto: 6, ttl: 61, id: 0x9a3e });
  h.tcp(p, { sport: 52211, dport: 443, seq: 2701000123, flags: 'SYN', dname: 'https' });
  return p;
}

PV.register({
  id: 'bgp', name: 'BGP', title: 'インターネットの経路交換', group: 'ネットワーク層', layerLabel: 'L3 の経路制御 · TCP 179',
  overview: {
    full: 'Border Gateway Protocol version 4',
    description: 'インターネットは、AS (自律システム: ISP や大企業などのネットワークのまとまり) の集まりです。BGP は隣り合う AS のルータ同士が「このネットワークには、この AS を順にたどれば行けます」と教え合うプロトコルで、これがインターネット全体の道順になります。',
    facts: [['トランスポート', 'TCP 179'], ['メッセージ', 'OPEN, UPDATE, KEEPALIVE, NOTIFICATION'], ['種類', 'eBGP (AS 間), iBGP (AS 内)'], ['経路の数', 'IPv4 で約 100 万経路 (2026 年)'], ['規格', 'RFC 4271, RFC 6793 (4 バイト AS)']],
  },
  nodes: {
    srv: { label: 'Web サーバ', sub: SRV, x: 70, y: 230, icon: 'server' },
    r1: { label: 'R1', sub: 'AS64500', x: 250, y: 230, icon: 'router' },
    r2: { label: 'R2', sub: 'AS64510', x: 500, y: 230, icon: 'router' },
    r3: { label: 'R3', sub: 'AS64520', x: 750, y: 230, icon: 'router' },
    user: { label: '利用者', sub: USER, x: 930, y: 230, icon: 'pc' },
  },
  links: [['srv', 'r1'], ['r1', 'r2'], ['r2', 'r3'], ['r3', 'user']],
  groups: [
    { label: 'AS64500 (コンテンツ事業者)', x: 15, y: 110, w: 330, h: 230 },
    { label: 'AS64510 (トランジット ISP)', x: 380, y: 110, w: 240, h: 230 },
    { label: 'AS64520 (アクセス ISP)', x: 655, y: 110, w: 330, h: 230 },
  ],
  lifelines: ['srv', 'r1', 'r2', 'r3', 'user'],
  legend: [['green', 'TCP'], ['amber', 'OPEN / KEEPALIVE'], ['violet', 'UPDATE (経路の広告)'], ['red', '経路の取り下げ'], ['blue', '利用者の通信'], ['gray', 'ルータ内の処理']],
  steps: [
    {
      title: 'TCP で接続する',
      desc: 'BGP は TCP の上で動きます。R1 と R2 は設定に書かれた相手 (neighbor) にポート 179 で接続します。',
      detail: 'BGP には相手を自動で見つける仕組みがありません。運用者が「192.0.2.2 は AS64510 の相手」と1つずつ設定します。AS 同士の接続 (eBGP) は、たいてい直結したリンクの両端で張ります。\n\nTCP を使うので、再送や順序の保証は TCP に任せられます。そのぶん BGP 自身は「変わった分だけ」を送る、シンプルな作りになっています。',
      facts: [['R1 側', '192.0.2.1 (AS64500)'], ['R2 側', '192.0.2.2 (AS64510)'], ['状態', 'Idle → Connect → OpenSent']],
      events: [
        ev('r1', 'r2', 'green', 'SYN', tcpCtl('r1', 'r2', 'SYN', 3804119021)),
        ev('r2', 'r1', 'green', 'SYN/ACK', tcpCtl('r2', 'r1', 'SYN,ACK', 1129044511)),
        ev('r1', 'r2', 'green', 'ACK', tcpCtl('r1', 'r2', 'ACK')),
      ],
    },
    {
      title: 'OPEN — 自己紹介',
      desc: 'お互いに AS 番号・ルータ ID・ホールドタイム・対応機能を伝えます。',
      detail: '受け取った側は、相手の AS 番号が設定どおりか (neighbor 192.0.2.1 remote-as 64500) を確認します。違っていれば NOTIFICATION を送って切断します。\n\nケーパビリティは「IPv4 ユニキャストの経路を交換したい」「4 バイト AS 番号に対応」などの機能の一覧で、両者が対応しているものだけが使われます。',
      events: [
        ev('r1', 'r2', 'amber', 'OPEN', open('r1', 'r2')),
        ev('r2', 'r1', 'amber', 'OPEN', open('r2', 'r1'), { with: true }),
        local('r2', 'AS 番号を確認', '受け取った OPEN の AS 番号 64500 が、設定 (neighbor 192.0.2.1 remote-as 64500) と一致。ホールドタイムは双方 90 秒なので 90 秒に決定。'),
      ],
    },
    {
      title: 'KEEPALIVE — セッション確立',
      desc: 'OPEN を受け入れた印に KEEPALIVE を返します。両方がそろうと Established (確立) になります。',
      detail: 'これで経路を交換する準備ができました。以後 KEEPALIVE はホールドタイムの 1/3 (30 秒) ごとに送られ、90 秒届かなければセッションを切ります。',
      facts: [['状態', 'OpenConfirm → Established'], ['KEEPALIVE 間隔', '30 秒'], ['ホールドタイム', '90 秒']],
      state: { r1: 'Established', r2: 'Established' },
      events: [
        ev('r1', 'r2', 'amber', 'KEEPALIVE', keepalive('r1', 'r2')),
        ev('r2', 'r1', 'amber', 'KEEPALIVE', keepalive('r2', 'r1'), { with: true }),
      ],
    },
    {
      title: 'UPDATE — 経路を広告する',
      desc: 'R1 は「203.0.113.0/24 は私 (AS64500) の先にあります」と R2 に教えます。',
      detail: 'UPDATE にはプレフィックス (NLRI) と、その経路の性質 (パス属性) が入っています。AS_PATH は通ってきた AS の列で、今は [64500] だけです。NEXT_HOP は「このネットワーク宛てのパケットは 192.0.2.1 に渡して」という意味です。\n\nR2 は受け取った経路を、そのまま使うわけではありません。フィルタ (この AS がこのプレフィックスを広告してよいか。IRR や RPKI で確認) を通し、他に同じプレフィックスへの経路があれば比べて、一番良いものを選びます。',
      facts: [['プレフィックス', PFX], ['AS_PATH', '64500'], ['NEXT_HOP', '192.0.2.1']],
      state: { r2: `${PFX} → R1` },
      events: [
        ev('r1', 'r2', 'violet', 'UPDATE', update('r1', 'r2', { asPath: [64500], nh: '192.0.2.1' })),
        local('r2', 'フィルタ → 経路選択', '1. 受信ポリシー: AS64500 は 203.0.113.0/24 を広告してよい (IRR に登録あり、RPKI の ROA でも Valid)\n\n2. 経路選択: LOCAL_PREF が高い → AS_PATH が短い → ORIGIN → MED → eBGP 優先 → … の順に比べる。今は経路が1本だけなのでこれが最良。\n\n3. 経路表 (RIB) に入れ、転送表 (FIB) にも反映する。'),
      ],
    },
    {
      title: '隣の AS へ伝わっていく',
      desc: 'R2 は自分の AS 番号を AS_PATH の先頭に足して、R3 にも広告します。',
      detail: 'AS_PATH は [64510 64500] になりました。R3 は「AS64510 → AS64500 とたどれば 203.0.113.0/24 に行ける」と分かります。こうして経路は AS から AS へと伝わり、数分以内に世界中のルータが知ることになります。\n\nもし受け取った AS_PATH に自分の AS 番号が入っていたら、その経路は捨てます。これが BGP のループ防止です。\n\n(R2 と R3 の間のセッションは、すでに R1-R2 と同じ手順で確立済みとしています。)',
      facts: [['AS_PATH', '64510 64500'], ['NEXT_HOP', '192.0.2.5 (R2 に書き換え)']],
      state: { r3: `${PFX} → R2` },
      events: [
        ev('r2', 'r3', 'violet', 'UPDATE', update('r2', 'r3', { asPath: [64510, 64500], nh: '192.0.2.5' })),
        local('r3', '経路表に登録', '203.0.113.0/24 → next hop 192.0.2.5 (AS_PATH 64510 64500) を経路表と転送表に登録。'),
      ],
    },
    {
      title: '経路に沿ってパケットが届く',
      desc: 'AS64520 の利用者が 203.0.113.10 にアクセスすると、各ルータは BGP で学んだ経路に従ってパケットを渡していきます。',
      detail: 'BGP はパケットを運ぶプロトコルではありません。BGP で作った「どこ宛てなら次は誰に渡すか」の表に従って、ルータが転送します。\n\n経路の広告とパケットの流れは逆向きになります。R1 → R2 → R3 と広告された経路を、パケットは R3 → R2 → R1 とたどります。',
      events: [
        ev('user', 'srv', 'blue', 'SYN :443', userSyn()),
      ],
    },
    {
      title: '経路を取り下げる',
      desc: 'AS64500 がメンテナンスでこのネットワークを止めると、R1 は「203.0.113.0/24 はもう使えません」と UPDATE で伝えます。',
      detail: '取り下げも UPDATE で送ります (Withdrawn Routes 欄)。R2 は経路表から消し、他に代わりの経路がなければ R3 にも取り下げを伝えます。\n\nBGP セッション自体が切れた場合 (ホールドタイム切れや NOTIFICATION) も、その相手から学んだ経路はすべて取り下げられます。大規模障害のときに経路が一斉に消えて「インターネットから見えなくなる」のは、この動きです。',
      state: { r2: '経路なし', r3: '経路なし' },
      events: [
        ev('r1', 'r2', 'red', 'UPDATE (取り下げ)', update('r1', 'r2', { withdraw: true })),
        ev('r2', 'r3', 'red', 'UPDATE (取り下げ)', update('r2', 'r3', { withdraw: true })),
      ],
    },
  ],
  outro: {
    title: '隣同士の「ここなら行けるよ」の積み重ねが、インターネットの地図になる',
    text: 'BGP のルータは、隣の AS から聞いた経路に自分の AS 番号を足して、さらに隣へ伝えます。全体を知っている誰かがいるわけではなく、隣同士のやりとりだけで世界中の道順ができあがっています。',
    points: [
      '経路選択は「最短」ではなく「ポリシー」。お金の流れ (顧客 > ピア > 上流) で LOCAL_PREF を決めるのが普通',
      '誤った広告 (経路ハイジャック・経路リーク) がそのまま広がってしまう弱点がある。RPKI (ROA) で「このプレフィックスはこの AS が広告してよい」を検証して防ぐ',
      'より長いプレフィックス (/24 より /25) が優先されるので、細かい経路を広告されると乗っ取られる',
      'eBGP は TTL 1 で直結の相手とだけ話す。GTSM では逆に TTL 255 で送って、受信側で 255 を確認する',
    ],
  },
});
})();
