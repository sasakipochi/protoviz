// DHCPv6: RA の M フラグを見て、リレー経由でアドレスと DNS をもらう
'use strict';
(() => {
const { pkt, h, ev, local, ip6, mac, be, tlv: T, dnsName } = PV;

const PC = { mac: '02:00:00:aa:00:10', ll: 'fe80::aa:10' };
const R = { mac: '02:00:5e:00:00:01', ll: 'fe80::1', lan: '2001:db8:10:1::1', up: '2001:db8:ff00::2' };
const SRV = { ip: '2001:db8:ff00::547', mac: '02:00:00:dd:05:47' };
const ADDR = '2001:db8:10:1::1a2b';
const DNS1 = '2001:db8:ff00::53';
const MT = { 1: 'Solicit', 2: 'Advertise', 3: 'Request', 7: 'Reply', 12: 'Relay-forward', 13: 'Relay-reply' };
const TX1 = [0x6a, 0x1f, 0x03], TX2 = [0x2b, 0x9e, 0x51];
const L = T.leaf;
const opt = (code, name, kids, value, desc) => T.node(`オプション ${code}: ${name}`, be(code, 2), 2, kids, { value, desc });
const o = {
  cid: () => opt(1, 'クライアント ID', [L('DUID 種別', be(3, 2), '3 (DUID-LL: MAC アドレスから作る)'), L('ハードウェア種別', be(1, 2), '1 (Ethernet)'), L('MAC アドレス', mac(PC.mac), PC.mac)], undefined, 'DUID: クライアントを識別する ID。DHCPv4 の chaddr にあたるが、MAC アドレスに限らない'),
  sid: () => opt(2, 'サーバ ID', [L('DUID 種別', be(1, 2), '1 (DUID-LLT: MAC + 時刻)'), L('ハードウェア種別', be(1, 2), '1 (Ethernet)'), L('時刻', be(0x2e8f1a00, 4), '0x2e8f1a00 (DUID を作った時刻)'), L('MAC アドレス', mac(SRV.mac), SRV.mac)]),
  ia: (addr, t1 = 0, t2 = 0) => opt(3, 'IA_NA (アドレスの入れ物)', [
    L('IAID', be(1, 4), '1', 'インターフェースごとの番号'),
    L('T1', be(t1, 4), t1 ? `${t1} 秒` : '0 (サーバにおまかせ)', '延長を頼む時刻'),
    L('T2', be(t2, 4), t2 ? `${t2} 秒` : '0 (サーバにおまかせ)'),
    ...(addr ? [opt(5, 'IA アドレス', [L('アドレス', ip6(addr), addr), L('推奨期間', be(3600, 4), '3600 秒'), L('有効期間', be(7200, 4), '7200 秒')], addr, 'オプションの中にオプションが入る')] : []),
  ], undefined, 'IA = Identity Association。「このインターフェースに貸すアドレスの束」'),
  et: (cs) => opt(8, '経過時間', [L('時間', be(cs, 2), `${cs / 100} 秒`)], undefined, '1/100 秒単位'),
  oro: () => opt(6, '要求するオプション', [L('23', be(23, 2), '23 (DNS サーバ)'), L('24', be(24, 2), '24 (ドメイン検索リスト)')]),
  dns: () => opt(23, 'DNS サーバ', [L('アドレス', ip6(DNS1), DNS1)]),
  dom: () => opt(24, 'ドメイン検索リスト', [L('名前', dnsName('corp.example'), '"corp.example" (DNS の名前の形式)')]),
};
// クライアントとサーバのメッセージ: 種別(1) + トランザクション ID(3) + オプション
function clientMsg(p, type, tx, opts) {
  p.layer(`DHCPv6 ${MT[type]}`)
    .u8('メッセージ種別', type, `${type} (${MT[type]})`)
    .f('トランザクション ID', tx, PV.hex(tx), '要求と応答を対応づける乱数 (3 バイト)');
  opts.forEach((n) => T.emit(p, n));
  return p;
}
// リレー: 中継したメッセージを丸ごと「リレーメッセージ」オプションに入れる
function relayMsg(p, type, inner) {
  const [itype, itx, iopts] = inner;
  const innerBytes = [itype, ...itx, ...iopts.flatMap(T.enc)];
  p.layer(`DHCPv6 ${MT[type]}`)
    .u8('メッセージ種別', type, `${type} (${MT[type]})`)
    .u8('ホップ数', 0, '0', 'リレーを何段重ねたか')
    .f('リンクアドレス', ip6(R.lan), R.lan, 'クライアントがいる LAN 上のリレーのアドレス。サーバはこれを見て、どのプレフィックスから貸すか決める (DHCPv4 の giaddr にあたる)')
    .f('ピアアドレス', ip6(PC.ll), PC.ll, 'クライアントのアドレス。応答を返す先')
    .f('オプション 18: インターフェース ID', [...be(18, 2), ...be(6, 2), ...PV.ascii('vlan10')], '"vlan10"', 'どのポートから来たかをリレーが覚えておくためのメモ。サーバはそのまま返してくる')
    .f(`オプション 9: リレーメッセージ`, [...be(9, 2), ...be(innerBytes.length, 2)], `長さ ${innerBytes.length}`, '中継しているメッセージそのもの');
  p.layer(`(中身) DHCPv6 ${MT[itype]}`)
    .u8('メッセージ種別', itype, `${itype} (${MT[itype]})`)
    .f('トランザクション ID', itx, PV.hex(itx));
  iopts.forEach((n) => T.emit(p, n));
  return p;
}
const clientOpts1 = [o.cid(), o.ia(), o.et(0), o.oro()];
const serverOpts = (t1, t2) => [o.sid(), o.cid(), o.ia(ADDR, t1, t2), o.dns(), o.dom()];
const reqOpts = [o.cid(), o.sid(), o.ia(ADDR), o.et(105), o.oro()];

function toServer(type, tx, opts) {
  const p = pkt(`中継: ${MT[type]} を DHCPv6 サーバへ`, { note: 'リレー (ルータ) は受け取ったメッセージを書き換えず、まるごと包んでサーバにユニキャストで送る。' });
  h.ipv6(p, { src: R.up, dst: SRV.ip, next: 17 });
  h.udp(p, { sport: 547, dport: 547, sname: 'dhcpv6-server', dname: 'dhcpv6-server' });
  return relayMsg(p, 12, [type, tx, opts]);
}
function fromServer(type, tx, opts) {
  const p = pkt(`中継: ${MT[type]} をリレーへ`);
  h.ipv6(p, { src: SRV.ip, dst: R.up, next: 17 });
  h.udp(p, { sport: 547, dport: 547, sname: 'dhcpv6-server', dname: 'dhcpv6-server' });
  return relayMsg(p, 13, [type, tx, opts]);
}
function fromClient(type, tx, opts, summary) {
  const p = pkt(summary);
  h.eth(p, { src: PC.mac, dst: '33:33:00:01:00:02', type: 0x86dd, dstName: 'DHCP リレー/サーバ全体' });
  h.ipv6(p, { src: PC.ll, dst: 'ff02::1:2', next: 17, hlim: 1 });
  h.udp(p, { sport: 546, dport: 547, sname: 'dhcpv6-client', dname: 'dhcpv6-server' });
  return clientMsg(p, type, tx, opts);
}
function toClient(type, tx, opts, summary) {
  const p = pkt(summary);
  h.eth(p, { src: R.mac, dst: PC.mac, type: 0x86dd, srcName: 'ルータ (リレー)' });
  h.ipv6(p, { src: R.ll, dst: PC.ll, next: 17 });
  h.udp(p, { sport: 547, dport: 546, sname: 'dhcpv6-server', dname: 'dhcpv6-client' });
  return clientMsg(p, type, tx, opts);
}

PV.register({
  id: 'dhcpv6', name: 'DHCPv6', title: 'IPv6 アドレスを管理して配る', group: 'LAN の中', layerLabel: 'L7 · UDP 546/547',
  overview: {
    full: 'Dynamic Host Configuration Protocol for IPv6',
    description: 'IPv6 では RA と SLAAC で端末が自分でアドレスを作れますが、「誰にどのアドレスを渡したか管理したい」組織では DHCPv6 を使います。RA の M フラグで「アドレスは DHCPv6 でもらって」と指示し、端末は Solicit → Advertise → Request → Reply の 4 段階でアドレスと DNS をもらいます。ブロードキャストの代わりにマルチキャスト ff02::1:2 を使い、既定のゲートウェイは今まで通り RA で知ります。',
    facts: [['層', 'アプリケーション層 (UDP)'], ['ポート', 'クライアント 546, サーバ/リレー 547'], ['宛先', 'ff02::1:2 (全 DHCP リレー/サーバ)'], ['流れ', 'Solicit → Advertise → Request → Reply'], ['ゲートウェイ', 'DHCPv6 では配らない (RA で知る)'], ['規格', 'RFC 8415']],
  },
  nodes: {
    pc: { label: 'PC', sub: PC.ll, x: 110, y: 205, icon: 'pc' },
    sw: { label: 'スイッチ', x: 300, y: 205, icon: 'relay' },
    router: { label: 'ルータ (リレー)', sub: R.lan, x: 500, y: 205, icon: 'router' },
    srv: { label: 'DHCPv6 サーバ', sub: SRV.ip, x: 860, y: 205, icon: 'server' },
  },
  links: [['pc', 'sw'], ['sw', 'router'], ['router', 'srv']],
  groups: [{ label: '社内 LAN 2001:db8:10:1::/64', x: 20, y: 60, w: 570, h: 290 }, { label: 'データセンター', x: 720, y: 60, w: 270, h: 290 }],
  lifelines: ['pc', 'router', 'srv'],
  legend: [['gray', '端末内の処理'], ['violet', 'ルータ広告 (RA)'], ['amber', 'クライアント → サーバ'], ['teal', 'サーバ → クライアント']],
  steps: [
    {
      title: 'RA が「DHCPv6 を使って」と言う',
      desc: 'ルータ広告 (RA) の M フラグが 1 なので、PC は SLAAC ではなく DHCPv6 でアドレスをもらいます。',
      detail: 'M (Managed) = 1 は「アドレスは DHCPv6 で」、O (Other) = 1 は「DNS などの情報は DHCPv6 で」の意味です。プレフィックス情報の A フラグを 0 にして、SLAAC でアドレスを作らないようにしています。L フラグは 1 のままなので、「この /64 は同じリンクにある」ことは RA から分かります。\n\n既定のゲートウェイは、今まで通り RA の送信元 (fe80::1) です。DHCPv6 にはゲートウェイを配るオプションがありません。',
      facts: [['フラグ', 'M=1, O=1'], ['プレフィックス', '2001:db8:10:1::/64 (L=1, A=0)'], ['ゲートウェイ', 'fe80::1 (RA の送信元)']],
      state: { pc: 'fe80::aa:10 のみ' },
      events: [
        ev('router', 'pc', 'violet', 'RA (M=1)', (() => {
          const p = pkt('ルータ広告: アドレスは DHCPv6 でもらってください (M=1)');
          h.eth(p, { src: R.mac, dst: '33:33:00:00:00:01', type: 0x86dd, srcName: 'ルータ', dstName: '全ノード' });
          h.ipv6(p, { src: R.ll, dst: 'ff02::1', next: 58, hlim: 255 });
          return p.layer('ICMPv6 Router Advertisement')
            .u8('タイプ', 134, '134 (Router Advertisement)').u8('コード', 0, '0')
            .f('チェックサム', [0, 0], '', undefined, h.icmp6csum())
            .u8('推奨ホップリミット', 64, '64')
            .u8('フラグ (M, O, …)', 0xc0, 'M=1, O=1', 'ここが DHCPv6 を使う合図')
            .u16('ルータ寿命', 1800, '1800 秒').u32('到達可能時間', 0, '0').u32('再送間隔', 0, '0')
            .u8('オプション: プレフィックス情報', 3, '3').u8('  長さ', 4, '4 (= 32 バイト)', undefined, { depth: 1 })
            .u8('  プレフィックス長', 64, '64', undefined, { depth: 1 })
            .u8('  フラグ (L, A)', 0x80, 'L=1, A=0', 'A=0: このプレフィックスで SLAAC をしないで', { depth: 1 })
            .u32('  有効期間', 2592000, '2592000 秒', undefined, { depth: 1 }).u32('  推奨期間', 604800, '604800 秒', undefined, { depth: 1 })
            .u32('  予約', 0, '0', undefined, { depth: 1 })
            .f('  プレフィックス', ip6('2001:db8:10:1::'), '2001:db8:10:1::', undefined, { depth: 1 });
        })()),
      ],
    },
    {
      title: 'サーバを探す (Solicit) → リレーが中継',
      desc: 'PC は ff02::1:2 (全 DHCP リレー/サーバ) 宛てに Solicit を送ります。ルータはリレーとして、それを包んでデータセンターのサーバへ送ります。',
      detail: '送信元は PC のリンクローカルアドレスです。DHCPv4 と違い、IPv6 では最初からリンクローカルアドレスがあるので 0.0.0.0 のような「名無し」で送る必要がありません。\n\nリレーは Solicit を書き換えず、Relay-forward メッセージの「リレーメッセージ」オプションに丸ごと入れます。リンクアドレス (2001:db8:10:1::1) を見たサーバは、「この LAN 用のアドレスを貸せばいい」と分かります。',
      facts: [['宛先', 'ff02::1:2 (ホップリミット 1)'], ['クライアント ID', 'DUID-LL (MAC アドレス由来)'], ['IA_NA', '空 (「アドレスをください」)']],
      events: [
        ev('pc', 'router', 'amber', 'Solicit', fromClient(1, TX1, clientOpts1, 'Solicit: DHCPv6 サーバはいますか？')),
        ev('router', 'srv', 'amber', 'Relay-forward', toServer(1, TX1, clientOpts1)),
      ],
    },
    {
      title: 'これをどうぞ (Advertise)',
      desc: `サーバが ${ADDR} を選び、DNS サーバとドメイン名を添えて申し出ます。リレーが中身を取り出して PC に渡します。`,
      detail: 'IA_NA オプションの中に IA アドレスオプションが入っている、入れ子の構造です。DHCPv6 のオプションは「種別 2 バイト + 長さ 2 バイト + 中身」で、DHCPv4 (1 バイト + 1 バイト) より大きくなりました。\n\nリレーは Relay-reply の中のメッセージを取り出し、ピアアドレス (PC のリンクローカルアドレス) 宛てに送ります。',
      facts: [['アドレス', ADDR], ['DNS', DNS1], ['ドメイン', 'corp.example']],
      state: { srv: `${ADDR} を仮押さえ` },
      events: [
        ev('srv', 'router', 'teal', 'Relay-reply', fromServer(2, TX1, serverOpts(1800, 2880))),
        ev('router', 'pc', 'teal', 'Advertise', toClient(2, TX1, serverOpts(1800, 2880), `Advertise: ${ADDR} はいかがですか`)),
      ],
    },
    {
      title: 'それをください (Request) → 確定 (Reply)',
      desc: 'PC が申し出を受けることを伝え、サーバが確定させます。流れは DHCPv4 の Request / Ack と同じです。',
      detail: 'Request にはサーバ ID を入れて「このサーバの申し出を受ける」と示し、IA_NA の中に欲しいアドレスを入れます。サーバは貸し出しをデータベースに記録し、Reply で確定させます。\n\nRapid Commit オプションを使えば、Solicit → Reply の 2 往復で済ませることもできます。',
      facts: [['T1 / T2', '1800 秒 / 2880 秒'], ['推奨期間 / 有効期間', '3600 秒 / 7200 秒']],
      state: { srv: `${ADDR} → DUID …aa:00:10` },
      events: [
        ev('pc', 'router', 'amber', 'Request', fromClient(3, TX2, reqOpts, `Request: ${ADDR} をください`)),
        ev('router', 'srv', 'amber', 'Relay-forward', toServer(3, TX2, reqOpts)),
        ev('srv', 'router', 'teal', 'Relay-reply', fromServer(7, TX2, serverOpts(1800, 2880))),
        ev('router', 'pc', 'teal', 'Reply', toClient(7, TX2, serverOpts(1800, 2880), `Reply: ${ADDR} を貸します`)),
      ],
    },
    {
      title: 'アドレスを設定する',
      desc: 'PC は受け取ったアドレスを /128 で設定し、DAD で重複を確かめてから使い始めます。',
      detail: 'DHCPv6 で配るのはアドレスだけで、プレフィックス長は含まれていません。そのため OS はアドレスを /128 として設定し、「2001:db8:10:1::/64 は同じリンク上にある」という情報は RA のプレフィックス情報 (L=1) から得ます。\n\nこのように、IPv6 では「RA (ゲートウェイ・リンク上のプレフィックス)」と「DHCPv6 (アドレス・DNS)」が役割を分担しています。',
      facts: [['アドレス', `${ADDR}/128`], ['同じリンク', '2001:db8:10:1::/64 (RA から)'], ['ゲートウェイ', 'fe80::1 (RA から)'], ['DNS', `${DNS1} (DHCPv6 から)`]],
      state: { pc: `${ADDR} ✓` },
      events: [local('pc', '/128 で設定 + DAD', `${ADDR}/128 を設定し、近隣要請で DAD を行う (ND のページを参照)。返事がないので使用開始。\n\nT1 (1800 秒) が過ぎたら Renew を ff02::1:2 に送って延長を頼む。`)],
    },
  ],
  outro: {
    title: 'RA と分担して、アドレスを管理する',
    text: 'DHCPv6 は、RA の M フラグを合図に、マルチキャスト ff02::1:2 でサーバを探し、4 段階でアドレスを借りました。サーバが別の LAN にあっても、ルータがリレーとして中継します。\n\nDHCPv4 と違ってゲートウェイを配らないので、RA と一緒に使うのが前提です。',
    points: [
      'DHCPv6-PD (プレフィックス委譲): 家庭用ルータが ISP から /56 や /48 をもらい、LAN ごとに /64 を切り出す。フレッツ光の IPv6 (IPoE) でも使われている',
      'Android は DHCPv6 のアドレス取得 (IA_NA) に対応していないため、M=1 だけの LAN では IPv6 アドレスを持てない',
      'クライアントは MAC アドレスではなく DUID で識別されるので、OS を入れ直すと DUID が変わって別人扱いになることがある',
      'O=1, M=0 の「ステートレス DHCPv6」は、アドレスは SLAAC、DNS などだけ DHCPv6 という使い方',
    ],
  },
});
})();
