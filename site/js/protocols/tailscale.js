// Tailscale: コーディネーションサーバで鍵を配り、NAT を越えて WireGuard で直接つなぐ
'use strict';
(() => {
const { pkt, h, ev, local, be, ip4, rand, ascii, hex } = PV;
const le = (n, size) => be(n, size).reverse();

const L_LAN = '192.168.1.23', L_PUB = '198.51.100.7', L_PORT = 61234;
const S_LAN = '10.0.0.5', S_PUB = '203.0.113.50', S_PORT = 41641;
const COORD = '192.0.2.10', DERP = '192.0.2.80';
const L_TS = '100.101.102.103', S_TS = '100.64.0.2';
const KEY = { laptopNode: rand('l-node', 32), serverNode: rand('s-node', 32), laptopDisco: rand('l-disco', 32), serverDisco: rand('s-disco', 32) };
const short = (b) => hex(b.slice(0, 4)).replace(/ /g, '') + '…';

const fromInternet = '回線上 (インターネット側) で見た形。NAT を通った後なので、送信元は自宅ルータのグローバルアドレスとポートに書き換わっている。';

// --- 制御サーバとの通信 (Noise で暗号化された HTTP) ---
function control(up, summary, json, note) {
  const body = ascii(json);
  const p = pkt(summary, { note: note || 'コーディネーションサーバとの通信は Noise プロトコル (WireGuard と同じ系統の暗号) で暗号化されている。HTTP の Upgrade で始まり、80 番が通らない環境では 443 番の TLS の中で行う。' });
  h.ipv4(p, up ? { src: L_PUB, dst: COORD, proto: 6, id: 0x0a01 } : { src: COORD, dst: L_PUB, proto: 6, id: 0x7701 });
  h.tcp(p, up ? { sport: 50744, dport: 80, seq: 1001, ack: 2001, flags: 'PSH,ACK', dname: 'http' } : { sport: 80, dport: 50744, seq: 2001, ack: 1001 + 200, flags: 'PSH,ACK', sname: 'http' });
  p.layer('Noise トランスポートフレーム')
    .u8('フレーム種別', 4, '4 (Record)', 'Noise で暗号化されたデータの入れ物')
    .u16('長さ', body.length + 16, String(body.length + 16))
    .blob('暗号文', `ctl-${summary}`, body.length, `(${body.length} バイト) 暗号化された HTTP/JSON`)
    .blob('認証タグ', `ctl-tag-${summary}`, 16, '(16 バイト)');
  p.layer('中身の JSON (要約)', { decoded: true, note: '実際は HTTP/2 の上でやりとりされ、MapResponse は zstd で圧縮されている。ここでは主な項目だけを読みやすく示している。' })
    .f('JSON', body, json.length > 60 ? json.slice(0, 60) + '…' : json, undefined);
  return p;
}

// --- STUN ---
function stun(resp) {
  const tx = rand('stun-tx', 12);
  const p = pkt(resp ? `STUN 応答: あなたは外から ${L_PUB}:${L_PORT} に見えます` : 'STUN 要求: 私は外からどう見えますか？', { note: resp ? undefined : fromInternet });
  h.ipv4(p, resp ? { src: DERP, dst: L_PUB, proto: 17, id: 0x3301 } : { src: L_PUB, dst: DERP, proto: 17, id: 0x0b01 });
  h.udp(p, resp ? { sport: 3478, dport: L_PORT, sname: 'stun' } : { sport: L_PORT, dport: 3478, dname: 'stun' });
  p.layer('STUN')
    .u16('メッセージ種別', resp ? 0x0101 : 0x0001, resp ? '0x0101 (Binding 成功応答)' : '0x0001 (Binding 要求)')
    .u16('長さ', 12, '12 バイト (ヘッダの後ろ)')
    .u32('マジッククッキー', 0x2112a442, '0x2112a442', 'STUN だと分かるための固定値')
    .f('トランザクション ID', tx, hex(tx), '要求と応答を対応づける乱数');
  if (!resp) {
    p.u16('属性: SOFTWARE', 0x8022, '0x8022 (SOFTWARE)').u16('  長さ', 8, '8', undefined, { depth: 1 }).str('  値', 'tailnode', undefined, { depth: 1 });
  } else {
    const ip = ip4(L_PUB), ck = [0x21, 0x12, 0xa4, 0x42];
    p.u16('属性: XOR-MAPPED-ADDRESS', 0x0020, '0x0020', 'サーバから見えた送信元アドレスとポート。NAT に書き換えられないように XOR で隠してある')
      .u16('  長さ', 8, '8', undefined, { depth: 1 })
      .u8('  予約', 0, '0', undefined, { depth: 1 }).u8('  ファミリ', 1, '1 (IPv4)', undefined, { depth: 1 })
      .u16('  ポート (XOR)', L_PORT ^ 0x2112, `${L_PORT} (= 0x${(L_PORT ^ 0x2112).toString(16)} XOR 0x2112)`, undefined, { depth: 1 })
      .f('  アドレス (XOR)', ip.map((b, i) => b ^ ck[i]), `${L_PUB} (XOR マジッククッキー)`, undefined, { depth: 1 });
  }
  return p;
}

// --- WireGuard メッセージ (中身として使う) ---
function wgInit(p, decoded) {
  return p.layer('WireGuard ハンドシェイク開始 (タイプ 1)', { decoded })
    .f('タイプ', [1, 0, 0, 0], '1 (Handshake Initiation)', '先頭 1 バイトが種別、残り 3 バイトは予約')
    .f('送信者インデックス', le(0x5e1a33c0, 4), '0x5e1a33c0', 'この接続を識別するための自分側の番号 (リトルエンディアン)')
    .blob('一時公開鍵', 'wg-eph-i', 32, '(32 バイト)', 'このハンドシェイク用に作った使い捨ての Curve25519 鍵')
    .blob('暗号化された静的公開鍵', 'wg-static', 48, '(32 + 16 バイト)', '自分のノード鍵 (公開鍵)。相手の公開鍵を使って暗号化してあるので、相手にしか読めない')
    .blob('暗号化されたタイムスタンプ', 'wg-ts', 28, '(12 + 16 バイト)', 'TAI64N 形式の時刻。古いハンドシェイクの再送り込みを防ぐ')
    .blob('MAC1', 'wg-mac1', 16, '(16 バイト)', '相手の公開鍵を知っている者だけが作れる値。知らない相手からのパケットは処理せずに捨てられる')
    .f('MAC2', Array(16).fill(0), '0 (未使用)', '高負荷時のクッキー用');
}
function wgResp(p, decoded) {
  return p.layer('WireGuard ハンドシェイク応答 (タイプ 2)', { decoded })
    .f('タイプ', [2, 0, 0, 0], '2 (Handshake Response)')
    .f('送信者インデックス', le(0x0b7d9e21, 4), '0x0b7d9e21')
    .f('受信者インデックス', le(0x5e1a33c0, 4), '0x5e1a33c0', '開始メッセージの送信者インデックス')
    .blob('一時公開鍵', 'wg-eph-r', 32, '(32 バイト)')
    .blob('暗号化された空データ', 'wg-empty', 16, '(0 + 16 バイト)', '中身は空。復号できることが「鍵の計算が一致した」証拠になる')
    .blob('MAC1', 'wg-mac1r', 16, '(16 バイト)')
    .f('MAC2', Array(16).fill(0), '0 (未使用)');
}

// --- DERP (TLS の中を流れる中継フレーム) ---
function derp(toDerp, from, summary, inner, innerLen, dstKey, note) {
  const fromLaptop = from === 'laptop';
  const pub = fromLaptop ? L_PUB : S_PUB;
  const p = pkt(summary, { note: note || 'DERP は HTTPS (TCP 443) の上で動く中継サーバ。UDP が通らない環境でも使える。DERP サーバが見えるのは「どの公開鍵宛てか」だけで、中身は WireGuard または disco の暗号で守られているので読めない。' });
  h.ipv4(p, toDerp ? { src: pub, dst: DERP, proto: 6, id: 0x0c01 } : { src: DERP, dst: pub, proto: 6, id: 0x3401 });
  h.tcp(p, toDerp ? { sport: fromLaptop ? 50812 : 39001, dport: 443, seq: 5001, ack: 9001, flags: 'PSH,ACK', dname: 'https' } : { sport: 443, dport: fromLaptop ? 50812 : 39001, seq: 9001, ack: 5001, flags: 'PSH,ACK', sname: 'https' });
  const frameLen = 5 + 32 + innerLen;
  p.layer('TLS レコード')
    .u8('種別', 23, '23 (アプリケーションデータ)').u16('バージョン', 0x0303, '0x0303 (TLS 1.2 表記。中身は TLS 1.3)')
    .u16('長さ', frameLen + 16, String(frameLen + 16))
    .blob('暗号文', `derp-tls-${summary}`, frameLen, `(${frameLen} バイト) DERP フレーム`)
    .blob('認証タグ', `derp-tag-${summary}`, 16, '(16 バイト)');
  p.layer(toDerp ? 'DERP フレーム: SendPacket' : 'DERP フレーム: RecvPacket', { decoded: true })
    .u8('フレーム種別', toDerp ? 4 : 5, toDerp ? '4 (SendPacket)' : '5 (RecvPacket)')
    .u32('長さ', 32 + innerLen, String(32 + innerLen))
    .f(toDerp ? '宛先の公開鍵' : '送信元の公開鍵', dstKey, short(dstKey), toDerp ? '「この鍵の持ち主に届けて」。DERP は IP アドレスではなく公開鍵で相手を区別する' : '誰から届いたか');
  inner(p);
  return p;
}
function discoMsg(p, decoded, sender, kind) {
  const len = { ping: 46, pong: 32, cmm: 2 + 18 * 2 }[kind];
  p.layer(`disco ${{ ping: 'Ping', pong: 'Pong', cmm: 'CallMeMaybe' }[kind]}`, { decoded })
    .f('マジック', [0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac], '"TS💬"', 'disco メッセージの印。WireGuard のパケットと区別するため')
    .f('送信者の disco 公開鍵', sender, short(sender), 'disco 専用の鍵。WireGuard の鍵とは別')
    .blob('ノンス', `disco-n-${kind}-${short(sender)}`, 24, '(24 バイト)')
    .blob('暗号文', `disco-c-${kind}-${short(sender)}`, len + 16, `(${len + 16} バイト)`, {
      ping: '中身: 種別 1 (Ping)、トランザクション ID、送信者のノード鍵',
      pong: '中身: 種別 2 (Pong)、トランザクション ID、「あなたのパケットは ○○:○○ から来ました」というアドレス',
      cmm: `中身: 種別 3 (CallMeMaybe)、自分のエンドポイント一覧 (${L_PUB}:${L_PORT}, ${L_LAN}:41641)。「今からそっちに直接送るから、そっちからも送って」`,
    }[kind]);
}
function directUdp(from, summary, build, note) {
  const fromLaptop = from === 'laptop';
  const p = pkt(summary, { note: note || fromInternet });
  h.ipv4(p, fromLaptop ? { src: L_PUB, dst: S_PUB, proto: 17, id: 0x0d01 } : { src: S_PUB, dst: L_PUB, proto: 17, id: 0x3501 });
  h.udp(p, fromLaptop ? { sport: L_PORT, dport: S_PORT } : { sport: S_PORT, dport: L_PORT });
  build(p);
  return p;
}
function wgData() {
  const inner = pkt('');
  h.ipv4(inner, { src: L_TS, dst: S_TS, proto: 6, id: 0x4c21, name: '中の IPv4 (Tailscale アドレス)' });
  h.tcp(inner, { sport: 48122, dport: 22, seq: 811900211, flags: 'SYN', dname: 'ssh' });
  inner.done();
  const n = 40;
  return directUdp('laptop', `WireGuard データ: ${L_TS} → ${S_TS}:22 (ssh)`, (p) => {
    p.layer('WireGuard データ (タイプ 4)')
      .f('タイプ', [4, 0, 0, 0], '4 (Transport Data)')
      .f('受信者インデックス', le(0x0b7d9e21, 4), '0x0b7d9e21', '相手側の番号。これでどのセッションの鍵で復号するかが決まる')
      .f('カウンタ', le(1, 8), '1', 'ノンスを兼ねる。毎回増えるので同じパケットの再送り込みは弾かれる')
      .blob('暗号文', 'wg-data', n, `(${n} バイト) 中の IP パケット`)
      .blob('認証タグ', 'wg-data-tag', 16, '(16 バイト)', 'ChaCha20-Poly1305 の改ざん検知');
    inner.layers.forEach((L) => p.layers.push({ ...L, decoded: true, fields: L.fields.map((f) => ({ ...f, calc: undefined })) }));
  }, '外から見えるのは UDP のパケットだけ。中には Tailscale のアドレス (100.x.y.z) 同士の普通の IP パケットが入っている。');
}

PV.register({
  id: 'tailscale', name: 'Tailscale', title: 'NAT を越えるメッシュ VPN', group: 'VPN・認証', layerLabel: 'L3 オーバーレイ · WireGuard (UDP 41641)',
  overview: {
    full: 'Tailscale — WireGuard + コーディネーションサーバ + DERP 中継',
    description: 'Tailscale は、どこにある端末同士でも、同じ LAN にいるかのように直接つなぐ VPN です。暗号化そのものは WireGuard。Tailscale が足しているのは「誰の公開鍵がどれか」を配るコーディネーションサーバと、NAT の向こうにいる相手と直接つながるための工夫 (STUN・disco・DERP 中継) です。',
    facts: [['データ', 'WireGuard (UDP, 既定 41641)'], ['制御', 'コーディネーションサーバ (鍵と設定の配布)'], ['中継', 'DERP (HTTPS 443)'], ['アドレス', '100.64.0.0/10 (CGNAT 範囲)'], ['暗号', 'Noise IK, Curve25519, ChaCha20-Poly1305']],
  },
  nodes: {
    laptop: { label: 'ノート PC', sub: `${L_TS}`, x: 80, y: 270, icon: 'pc' },
    nata: { label: '自宅ルータ (NAT)', sub: L_PUB, x: 250, y: 270, icon: 'nat' },
    inet: { label: 'インターネット', x: 500, y: 270, icon: 'cloud' },
    natb: { label: '会社の NAT', sub: S_PUB, x: 750, y: 270, icon: 'nat' },
    server: { label: '社内サーバ', sub: `${S_TS}`, x: 920, y: 270, icon: 'server' },
    coord: { label: 'コーディネーション', sub: 'controlplane', x: 380, y: 85, icon: 'key' },
    derp: { label: 'DERP 中継', sub: `Tokyo ${DERP}`, x: 620, y: 85, icon: 'relay' },
  },
  links: [['laptop', 'nata'], ['nata', 'inet'], ['inet', 'natb'], ['natb', 'server'], ['inet', 'coord'], ['inet', 'derp']],
  groups: [
    { label: `自宅 LAN (PC は ${L_LAN})`, x: 15, y: 190, w: 310, h: 170 },
    { label: `会社 LAN (サーバは ${S_LAN})`, x: 675, y: 190, w: 310, h: 170 },
    { label: 'Tailscale 社が運用', x: 290, y: 15, w: 420, h: 135 },
  ],
  height: 380,
  lifelines: ['laptop', 'coord', 'derp', 'server'],
  legend: [['gray', '端末内の処理'], ['amber', '制御 (鍵・設定の配布)'], ['teal', 'STUN'], ['pink', 'disco (NAT 越えの合図)'], ['violet', 'WireGuard ハンドシェイク'], ['green', 'WireGuard データ']],
  steps: [
    {
      title: '鍵を作る',
      desc: '各端末は自分で鍵ペアを作ります。秘密鍵は端末から一歩も出ません。',
      detail: '作る鍵は主に3つです。マシン鍵 (端末そのものを表す)、ノード鍵 (WireGuard で使う。ログインし直すと変わる)、disco 鍵 (NAT 越えの合図用)。サーバに送るのは公開鍵だけです。\n\nコーディネーションサーバは公開鍵を配るだけなので、通信の中身を読むことはできません。',
      facts: [['ノート PC のノード鍵', `nodekey:${short(KEY.laptopNode)}`], ['サーバのノード鍵', `nodekey:${short(KEY.serverNode)}`]],
      state: { laptop: '🔑 鍵生成', server: '🔑 鍵生成' },
      events: [
        local('laptop', '鍵ペアを生成', 'マシン鍵・ノード鍵・disco 鍵の3組の Curve25519 鍵ペアを生成。秘密鍵は /var/lib/tailscale/ (Linux の場合) に保存され、外に出ることはない。'),
        local('server', '鍵ペアを生成', '社内サーバも同じように自分の鍵ペアを作る (すでにログイン済みとする)。', { with: true }),
      ],
    },
    {
      title: 'ログインして登録する',
      desc: 'ノート PC はコーディネーションサーバに公開鍵を送り、利用者が SSO (Google, Microsoft など) でログインして、端末を自分の tailnet に登録します。',
      detail: '初回は登録要求に対して「このURLでログインして」という応答が返り、ブラウザでログインすると登録が完了します。以後はノード鍵が期限切れ (既定 180 日) になるまで、ログインし直す必要はありません。\n\nTailscale のアドレス (100.101.102.103) はこのとき割り当てられ、端末が変わらない限り同じです。',
      state: { laptop: `${L_TS}`, coord: '端末を登録' },
      events: [
        ev('laptop', 'coord', 'amber', 'RegisterRequest', control(true, 'RegisterRequest: この公開鍵を登録して', `{"NodeKey":"nodekey:${short(KEY.laptopNode)}","Hostinfo":{"Hostname":"laptop","OS":"linux"},"Followup":""}`)),
        ev('coord', 'laptop', 'amber', 'AuthURL', control(false, 'RegisterResponse: このURLでログインして', '{"AuthURL":"https://login.tailscale.com/a/1a2b3c4d5e","MachineAuthorized":false}')),
        local('laptop', 'ブラウザで SSO ログイン', '利用者がブラウザで AuthURL を開き、会社の Google アカウントなどでログインする。管理者の承認が必要な設定なら、ここで承認を待つ。'),
        ev('coord', 'laptop', 'amber', '登録完了', control(false, 'RegisterResponse: 登録完了', `{"User":{"LoginName":"alice@example.com"},"MachineAuthorized":true,"NodeKeyExpiry":"2027-05-05T00:00:00Z"}`)),
      ],
    },
    {
      title: 'ネットワークマップを受け取る',
      desc: 'ノート PC は MapRequest を送り、通信してよい相手の一覧 (公開鍵・アドレス・エンドポイント) を受け取ります。',
      detail: 'この接続は開いたままになっていて (ロングポーリング)、誰かが参加したりアドレスが変わったりすると、コーディネーションサーバから更新が届きます。\n\n一覧に入るのは ACL (アクセス制御) で通信が許されている相手だけです。社内サーバ側にも「ノート PC が参加した」という更新が届きます。',
      facts: [['相手のノード鍵', `nodekey:${short(KEY.serverNode)}`], ['相手のアドレス', `${S_TS}/32`], ['相手のエンドポイント', `${S_PUB}:${S_PORT}, ${S_LAN}:${S_PORT}`], ['相手のホーム DERP', 'Tokyo']],
      state: { laptop: `${L_TS} · 相手 1 台` },
      events: [
        ev('laptop', 'coord', 'amber', 'MapRequest', control(true, 'MapRequest: 通信相手の一覧をください (以後の変更も送って)', `{"NodeKey":"nodekey:${short(KEY.laptopNode)}","DiscoKey":"discokey:${short(KEY.laptopDisco)}","Stream":true,"Endpoints":["${L_LAN}:41641"]}`)),
        ev('coord', 'laptop', 'amber', 'MapResponse', control(false, 'MapResponse: ネットワークマップ', `{"Node":{"Addresses":["${L_TS}/32"]},"Peers":[{"Name":"server","Key":"nodekey:${short(KEY.serverNode)}","DiscoKey":"discokey:${short(KEY.serverDisco)}","Addresses":["${S_TS}/32"],"Endpoints":["${S_PUB}:${S_PORT}","${S_LAN}:${S_PORT}"],"HomeDERP":"Tokyo"}],"PacketFilter":[…],"DNSConfig":{…}}`)),
        ev('coord', 'server', 'amber', 'MapResponse (更新)', control(false, 'MapResponse (差分): 新しい相手 laptop が参加', `{"PeersChanged":[{"Name":"laptop","Key":"nodekey:${short(KEY.laptopNode)}","Addresses":["${L_TS}/32"],"Endpoints":["${L_LAN}:41641"],"HomeDERP":"Tokyo"}]}`, '社内サーバ宛ての更新。社内サーバも同じようにコーディネーションサーバとつながったままになっている。'), { with: true }),
      ],
    },
    {
      title: '外からどう見えているか調べる (STUN)',
      desc: 'NAT の内側にいるノート PC は、自分が外からどのアドレス・ポートに見えているかを知りません。そこで DERP サーバの STUN に尋ねます。',
      detail: '自宅ルータは、ノート PC の 192.168.1.23:41641 を 198.51.100.7:61234 に変換して外に出しています。STUN サーバは「あなたのパケットは 198.51.100.7:61234 から来た」と教えてくれます。\n\nこの外側のアドレスを、エンドポイントとしてコーディネーションサーバに報告します。すると社内サーバにも伝わり、お互いに「相手に直接送るならこのアドレス」が分かります。',
      facts: [['内側', `${L_LAN}:41641`], ['外側 (NAT 変換後)', `${L_PUB}:${L_PORT}`]],
      events: [
        ev('laptop', 'derp', 'teal', 'STUN 要求', stun(false)),
        ev('derp', 'laptop', 'teal', 'STUN 応答', stun(true)),
        ev('laptop', 'coord', 'amber', 'エンドポイント報告', control(true, 'MapRequest: 私のエンドポイントが増えました', `{"Endpoints":["${L_PUB}:${L_PORT}","${L_LAN}:41641"],"EndpointTypes":["stun","local"]}`)),
        ev('coord', 'server', 'amber', '更新を配布', control(false, 'MapResponse (差分): laptop のエンドポイント', `{"PeersChangedPatch":[{"Key":"nodekey:${short(KEY.laptopNode)}","Endpoints":["${L_PUB}:${L_PORT}","${L_LAN}:41641"]}]}`, '社内サーバ宛ての更新。')),
      ],
    },
    {
      title: 'まずは DERP 経由でつなぐ',
      desc: '直接つながるか分からないうちは、DERP 中継サーバ経由で WireGuard のハンドシェイクを始めます。すぐに通信を始められます。',
      detail: 'ノート PC が社内サーバ (100.64.0.2) に ssh しようとすると、WireGuard がハンドシェイク開始メッセージを作ります。Tailscale はこれを DERP サーバに渡し、DERP は宛先の公開鍵につながっている社内サーバに届けます。\n\nDERP は中身を復号できません。WireGuard の暗号は端末同士で完結しているからです。',
      state: { laptop: 'DERP 経由で接続', server: 'DERP 経由で接続' },
      events: [
        ev('laptop', 'derp', 'violet', 'WG 開始 (DERP)', derp(true, 'laptop', 'DERP SendPacket: WireGuard ハンドシェイク開始を server へ', (p) => wgInit(p, true), 148, KEY.serverNode)),
        ev('derp', 'server', 'violet', 'WG 開始 (DERP)', derp(false, 'server', 'DERP RecvPacket: laptop からのハンドシェイク開始', (p) => wgInit(p, true), 148, KEY.laptopNode)),
        ev('server', 'derp', 'violet', 'WG 応答 (DERP)', derp(true, 'server', 'DERP SendPacket: WireGuard ハンドシェイク応答を laptop へ', (p) => wgResp(p, true), 92, KEY.laptopNode)),
        ev('derp', 'laptop', 'violet', 'WG 応答 (DERP)', derp(false, 'laptop', 'DERP RecvPacket: server からのハンドシェイク応答', (p) => wgResp(p, true), 92, KEY.serverNode)),
      ],
    },
    {
      title: 'NAT に穴を開ける (disco)',
      desc: '並行して、お互いのエンドポイントに直接 UDP を送り合います。両側から同時に送ることで、両方の NAT に「返事の通り道」ができます。',
      detail: 'NAT は「内側から外に送ったことがある相手」からの返事だけを通します。そこで CallMeMaybe (DERP 経由) で「今から送るから、そっちからも送って」と合図し、両方から相手のエンドポイントへ disco Ping を送ります。\n\n自分の NAT に穴が開いた状態で相手の Ping が届けば成功です。Pong が返ってくれば、その経路が使えると確定します。この手法を UDP ホールパンチングと呼びます。',
      events: [
        ev('laptop', 'derp', 'pink', 'CallMeMaybe', derp(true, 'laptop', 'DERP SendPacket: disco CallMeMaybe', (p) => discoMsg(p, true, KEY.laptopDisco, 'cmm'), 6 + 32 + 24 + 38 + 16, KEY.serverNode)),
        ev('derp', 'server', 'pink', 'CallMeMaybe', derp(false, 'server', 'DERP RecvPacket: disco CallMeMaybe', (p) => discoMsg(p, true, KEY.laptopDisco, 'cmm'), 6 + 32 + 24 + 38 + 16, KEY.laptopNode)),
        ev('laptop', 'server', 'pink', 'disco Ping', directUdp('laptop', `disco Ping: ${L_PUB}:${L_PORT} → ${S_PUB}:${S_PORT}`, (p) => discoMsg(p, false, KEY.laptopDisco, 'ping'))),
        ev('server', 'laptop', 'pink', 'disco Ping', directUdp('server', `disco Ping: ${S_PUB}:${S_PORT} → ${L_PUB}:${L_PORT}`, (p) => discoMsg(p, false, KEY.serverDisco, 'ping')), { with: true }),
        ev('server', 'laptop', 'pink', 'disco Pong', directUdp('server', 'disco Pong: 届いたよ', (p) => discoMsg(p, false, KEY.serverDisco, 'pong'))),
        local('laptop', '直接経路を採用', `Pong が返ってきたので ${S_PUB}:${S_PORT} への直接経路が使えると判断。往復時間も DERP 経由より短いので、以後のパケットは直接送る。DERP 経由の経路は予備として残す。`),
      ],
    },
    {
      title: '直接 WireGuard で通信する',
      desc: '以後のデータは DERP を通らず、ノート PC と社内サーバの間を直接流れます。',
      detail: 'インターネット上に見えるのは、2つのグローバルアドレスの間を流れる UDP パケットだけです。中には 100.101.102.103 → 100.64.0.2 の普通の IP パケット (ここでは ssh の接続開始) が、WireGuard で暗号化されて入っています。\n\n社内サーバは復号した後、ACL (パケットフィルタ) で通信が許されているかを確認してから受け取ります。',
      state: { laptop: '直接接続 ✓', server: '直接接続 ✓' },
      events: [
        ev('laptop', 'server', 'green', 'WG データ', wgData()),
      ],
    },
  ],
  outro: {
    title: '鍵を配るのはサーバ、通信は端末同士で直接',
    text: 'Tailscale のコーディネーションサーバは公開鍵とエンドポイントを配るだけで、データの通り道にはなりません。端末同士は STUN で外側のアドレスを調べ、disco で NAT に穴を開け、WireGuard で直接暗号化通信します。直接つながらないときだけ DERP が中継します。',
    points: [
      'tailscale status や tailscale ping で、相手と直接 (direct) か中継 (relay "tok") かが分かる',
      '両側が「ポートの割り当てが宛先ごとに変わる NAT」(Symmetric NAT) だと直接つながりにくく、DERP 経由になる',
      'コーディネーションサーバが止まっても、すでにつながっている端末同士の通信は続く (新しい鍵の配布ができなくなるだけ)',
      'コーディネーションサーバを自前で立てる互換実装として Headscale がある',
    ],
  },
});
})();
