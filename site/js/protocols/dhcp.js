// DHCP (IPv4): Discover → Offer → Request → Ack でアドレスを借りる
'use strict';
(() => {
const { pkt, h, ev, local, ip4, mac, ascii, tlv: T, hex } = PV;

const PC = { mac: '02:00:00:aa:00:10' };
const PCB = { mac: '02:00:00:bb:00:20', ip: '192.0.2.101' };
const SRV = { mac: '02:00:5e:00:00:01', ip: '192.0.2.1' };
const LEASE = '192.0.2.100';
const XID = 0x3903f326, XID2 = 0x5c1e0a77;
const BC = 'ff:ff:ff:ff:ff:ff';
const MT = { 1: 'DHCPDISCOVER', 2: 'DHCPOFFER', 3: 'DHCPREQUEST', 5: 'DHCPACK' };

const opt = (code, name, kids, value, desc) => T.node(`オプション ${code}: ${name}`, [code], 1, kids, { value, desc });
const L = T.leaf;
const o = {
  type: (t) => opt(53, 'メッセージ種別', [L('種別', [t], `${t} (${MT[t]})`)], MT[t], 'DHCP のどの段階のメッセージか。BOOTP との違いはほぼこのオプションだけで表される'),
  cid: () => opt(61, 'クライアント ID', [L('ハードウェア種別', [1], '1 (Ethernet)'), L('MAC アドレス', mac(PC.mac), PC.mac)], undefined, 'サーバが「誰に貸したか」を覚えるときの鍵'),
  req: (ip) => opt(50, '要求する IP アドレス', [L('アドレス', ip4(ip), ip)], ip, '「このアドレスをください」'),
  sid: () => opt(54, 'サーバ ID', [L('アドレス', ip4(SRV.ip), SRV.ip)], SRV.ip, 'どのサーバの申し出を受けるか (サーバが複数いるとき用)'),
  host: () => opt(12, 'ホスト名', [L('名前', ascii('laptop-01'), '"laptop-01"')]),
  prl: () => opt(55, '要求するパラメータ', [L('1', [1], '1 (サブネットマスク)'), L('3', [3], '3 (ルータ)'), L('6', [6], '6 (DNS サーバ)'), L('15', [15], '15 (ドメイン名)'), L('119', [119], '119 (ドメイン検索リスト)')], undefined, 'クライアントが欲しい設定の一覧'),
  u32: (code, name, sec, desc) => opt(code, name, [L('秒', PV.be(sec, 4), `${sec} 秒`)], `${sec} 秒`, desc),
  addr: (code, name, ip, desc) => opt(code, name, [L('アドレス', ip4(ip), ip)], ip, desc),
  domain: () => opt(15, 'ドメイン名', [L('名前', ascii('home.example'), '"home.example"')]),
  end: () => L('オプション 255: 終わり', [255], '終わり'),
};
const serverOpts = (t) => [o.type(t), o.sid(),
  o.u32(51, 'リース時間', 86400, '貸し出す期間 (24 時間)'),
  o.u32(58, '更新時間 (T1)', 43200, 'この時間が過ぎたら、借りたサーバに延長を頼む (リースの半分)'),
  o.u32(59, '再バインド時間 (T2)', 75600, 'ここまで延長できなければ、どのサーバでもよいから頼む (リースの 7/8)'),
  o.addr(1, 'サブネットマスク', '255.255.255.0'), o.addr(3, 'ルータ', SRV.ip, '既定のゲートウェイ'),
  o.addr(6, 'DNS サーバ', SRV.ip), o.domain(), o.end()];

// BOOTP 形式の固定部分 (236 バイト) + マジッククッキー + オプション
function dhcp(p, { op, xid, ciaddr = '0.0.0.0', yiaddr = '0.0.0.0', siaddr = '0.0.0.0', secs = 0, opts }) {
  p.layer(`DHCP ${MT[opts[0].kids[0].bytes[0]]}`)
    .u8('op', op, op === 1 ? '1 (BOOTREQUEST)' : '2 (BOOTREPLY)', 'クライアント → サーバは 1、逆は 2。BOOTP の名残')
    .u8('ハードウェア種別', 1, '1 (Ethernet)').u8('ハードウェアアドレス長', 6, '6').u8('ホップ数', 0, '0', 'リレーエージェントを通るたびに増える')
    .u32('トランザクション ID', xid, '0x' + xid.toString(16), 'クライアントが決めた乱数。要求と応答の組を対応づける')
    .u16('経過秒数', secs, `${secs} 秒`, '取得を始めてからの時間')
    .u16('フラグ', 0, '0 (ブロードキャスト不要)', '最上位ビットが 1 なら「応答をブロードキャストで送って」')
    .f('ciaddr (クライアントの今の IP)', ip4(ciaddr), ciaddr, 'すでにアドレスを持っている (更新時) ときだけ入れる')
    .f('yiaddr (あなたの IP)', ip4(yiaddr), yiaddr, 'サーバが貸すアドレス')
    .f('siaddr (次のサーバ)', ip4(siaddr), siaddr, 'ネットワークブートで次にファイルを取りに行くサーバ')
    .f('giaddr (リレーエージェント)', ip4('0.0.0.0'), '0.0.0.0', 'ルータが中継したときに、ルータの LAN 側アドレスが入る。サーバはこれでどの LAN 用のアドレスを貸すか決める')
    .f('chaddr (クライアントの MAC)', [...mac(PC.mac), ...Array(10).fill(0)], PC.mac, '16 バイトの欄の先頭 6 バイト')
    .f('sname (サーバ名)', Array(64).fill(0), '(空 64 バイト)', 'BOOTP の名残。今はほぼ使わない')
    .f('file (ブートファイル名)', Array(128).fill(0), '(空 128 バイト)', 'PXE ブートのときはここにファイル名が入る')
    .u32('マジッククッキー', 0x63825363, '0x63825363', 'ここから後ろが DHCP のオプションだという目印');
  opts.forEach((n) => T.emit(p, n));
  const used = 240 + opts.reduce((a, n) => a + T.enc(n).length, 0);
  if (used < 300) p.f('パディング', Array(300 - used).fill(0), `00 × ${300 - used}`, '古い BOOTP の実装との互換のため、全体を 300 バイト以上にする');
  return p;
}

PV.register({
  id: 'dhcp', name: 'DHCP', title: 'IPv4 アドレスを借りる', group: 'LAN の中', layerLabel: 'L7 · UDP 67/68',
  overview: {
    full: 'Dynamic Host Configuration Protocol',
    description: 'LAN につないだ PC が、IP アドレス・サブネットマスク・ゲートウェイ・DNS サーバを DHCP サーバから借ります。まだ IP アドレスを持っていないので、最初はブロードキャストで「誰か貸して」と叫びます。アドレスは期限付きの貸し出し (リース) で、期限の半分が過ぎると延長を頼みます。メッセージの形は 1985 年の BOOTP をそのまま受け継いでいます。',
    facts: [['層', 'アプリケーション層 (UDP)'], ['ポート', 'サーバ 67, クライアント 68'], ['流れ', 'Discover → Offer → Request → Ack (DORA)'], ['最初の宛先', '255.255.255.255 (ブロードキャスト)'], ['前身', 'BOOTP (RFC 951), RARP'], ['規格', 'RFC 2131, RFC 2132']],
  },
  nodes: {
    pc: { label: 'PC', sub: PC.mac, x: 110, y: 110, icon: 'pc' },
    pcb: { label: '他の PC', sub: PCB.ip, x: 110, y: 300, icon: 'pc' },
    sw: { label: 'スイッチ', x: 360, y: 205, icon: 'relay' },
    srv: { label: 'ルータ (DHCP サーバ)', sub: SRV.ip, x: 610, y: 205, icon: 'router' },
    inet: { label: 'インターネット', x: 870, y: 205, icon: 'cloud' },
  },
  links: [['pc', 'sw'], ['pcb', 'sw'], ['sw', 'srv'], ['srv', 'inet']],
  groups: [{ label: 'LAN 192.0.2.0/24 (アドレスの貸出範囲 .100〜.199)', x: 20, y: 30, w: 700, h: 340 }],
  lifelines: ['pc', 'pcb', 'srv'],
  legend: [['gray', '端末内の処理'], ['amber', 'クライアント → サーバ'], ['teal', 'サーバ → クライアント']],
  steps: [
    {
      title: '誰か貸してください (Discover)',
      desc: 'IP アドレスを持たない PC が、LAN 全体に「DHCP サーバはいますか」とブロードキャストします。',
      detail: '送信元 IP は 0.0.0.0、宛先 IP は 255.255.255.255、宛先 MAC は ff:ff:ff:ff:ff:ff です。自分のアドレスがないので名乗れず、サーバの場所も知らないので全員に送ります。\n\nメッセージの大部分は BOOTP の固定の欄で、sname (64 バイト) や file (128 バイト) のように今はほとんど使わない欄も残っています。DHCP 独自の情報はマジッククッキーの後ろの「オプション」に入ります。',
      facts: [['送信元', '0.0.0.0:68'], ['宛先', '255.255.255.255:67'], ['トランザクション ID', '0x' + XID.toString(16)]],
      state: { pc: 'IP: なし' },
      events: [
        ev('pc', ['pcb', 'srv'], 'amber', 'DHCPDISCOVER', (() => {
          const p = pkt('DHCPDISCOVER: DHCP サーバはいますか？');
          h.eth(p, { src: PC.mac, dst: BC, type: 0x0800, dstName: 'ブロードキャスト' });
          h.ipv4(p, { src: '0.0.0.0', dst: '255.255.255.255', proto: 17, ttl: 64, df: false, tos: 0x10 });
          h.udp(p, { sport: 68, dport: 67, sname: 'bootpc', dname: 'bootps' });
          return dhcp(p, { op: 1, xid: XID, opts: [o.type(1), o.cid(), o.req(LEASE), o.host(), o.prl(), o.end()] });
        })()),
        local('pcb', 'ポート 67 を聞いていない → 捨てる', 'ブロードキャストなので OS までは届くが、DHCP サーバではないので UDP 67 番を待ち受けておらず、破棄する。'),
      ],
    },
    {
      title: 'これをどうぞ (Offer)',
      desc: 'サーバが空いているアドレスを選び、「192.0.2.100 はいかがですか」と申し出ます。',
      detail: `PC は「前回使った ${LEASE} がいい」とオプション 50 で希望していました。空いていたので、サーバはそのアドレスを選びました。\n\nこの時点ではまだ「仮押さえ」で、貸し出しは確定していません。サーバは申し出る前に、そのアドレスに ping を送って誰も使っていないかを確かめることもあります。\n\nブロードキャストフラグが 0 なので、サーバは PC の MAC アドレス宛てのユニキャストで答えます (宛先 IP は貸す予定の ${LEASE})。`,
      facts: [['yiaddr', LEASE], ['リース時間', '86400 秒 (24 時間)'], ['ルータ / DNS', SRV.ip]],
      state: { srv: `${LEASE} を仮押さえ` },
      events: [
        ev('srv', 'pc', 'teal', 'DHCPOFFER', (() => {
          const p = pkt(`DHCPOFFER: ${LEASE} はいかがですか`);
          h.eth(p, { src: SRV.mac, dst: PC.mac, type: 0x0800, srcName: 'DHCP サーバ' });
          h.ipv4(p, { src: SRV.ip, dst: LEASE, proto: 17, ttl: 64, id: 0x2001, df: false });
          h.udp(p, { sport: 67, dport: 68, sname: 'bootps', dname: 'bootpc' });
          return dhcp(p, { op: 2, xid: XID, yiaddr: LEASE, opts: serverOpts(2) });
        })()),
      ],
    },
    {
      title: 'それをください (Request)',
      desc: 'PC は申し出を受けることを、もう一度ブロードキャストで伝えます。',
      detail: 'まだアドレスが確定していないので、送信元は 0.0.0.0 のままです。ブロードキャストにするのは、DHCP サーバが複数いた場合に「あなたの申し出は断ります」と他のサーバにも伝えるためです。どのサーバの申し出を受けるかは、オプション 54 (サーバ ID) で示します。',
      facts: [['要求する IP', LEASE], ['サーバ ID', SRV.ip], ['宛先', '255.255.255.255 (他のサーバにも聞こえるように)']],
      events: [
        ev('pc', ['pcb', 'srv'], 'amber', 'DHCPREQUEST', (() => {
          const p = pkt(`DHCPREQUEST: ${SRV.ip} さんの ${LEASE} をください`);
          h.eth(p, { src: PC.mac, dst: BC, type: 0x0800, dstName: 'ブロードキャスト' });
          h.ipv4(p, { src: '0.0.0.0', dst: '255.255.255.255', proto: 17, ttl: 64, df: false, tos: 0x10 });
          h.udp(p, { sport: 68, dport: 67, sname: 'bootpc', dname: 'bootps' });
          return dhcp(p, { op: 1, xid: XID, secs: 1, opts: [o.type(3), o.cid(), o.req(LEASE), o.sid(), o.host(), o.prl(), o.end()] });
        })()),
      ],
    },
    {
      title: '貸し出し確定 (Ack)',
      desc: 'サーバが貸し出しを記録し、確定を知らせます。PC はアドレスを設定して通信を始めます。',
      detail: 'サーバは「この MAC (クライアント ID) にこのアドレスを、いつまで貸した」をリースのデータベースに書き込みます。\n\n受け取った PC は、念のため ARP Probe でそのアドレスを使っている人がいないか確かめてから設定します。誰かが使っていたら DHCPDECLINE を送ってやり直します。',
      facts: [['IP アドレス', `${LEASE}/24`], ['ゲートウェイ', SRV.ip], ['DNS', SRV.ip], ['期限', '24 時間後 (12 時間後に延長を頼む)']],
      state: { pc: `IP: ${LEASE}`, srv: `${LEASE} → ${PC.mac}` },
      events: [
        ev('srv', 'pc', 'teal', 'DHCPACK', (() => {
          const p = pkt(`DHCPACK: ${LEASE} を 24 時間貸します`);
          h.eth(p, { src: SRV.mac, dst: PC.mac, type: 0x0800, srcName: 'DHCP サーバ' });
          h.ipv4(p, { src: SRV.ip, dst: LEASE, proto: 17, ttl: 64, id: 0x2002, df: false });
          h.udp(p, { sport: 67, dport: 68, sname: 'bootps', dname: 'bootpc' });
          return dhcp(p, { op: 2, xid: XID, yiaddr: LEASE, opts: serverOpts(5) });
        })()),
        local('pc', 'ARP Probe → 設定', `ARP で ${LEASE} を使っている人がいないか確かめ (ARP のページを参照)、返事がないのでインターフェースに ${LEASE}/24、既定の経路 ${SRV.ip}、DNS ${SRV.ip} を設定する。`),
      ],
    },
    {
      title: '12 時間後: 延長を頼む (Renew)',
      desc: 'リースの半分 (T1) が過ぎると、PC は借りたサーバに直接 (ユニキャストで) 延長を頼みます。',
      detail: 'もうアドレスを持っているので、送信元 IP は自分のアドレス、宛先はサーバのアドレスです。ciaddr 欄にも今のアドレスを入れます。サーバが Ack を返せば、期限がそこからまた 24 時間に延びます。\n\nサーバが答えないまま T2 (7/8) を過ぎると、ブロードキャストで「どのサーバでもいいから延長して」と頼みます (Rebind)。それも駄目でリースが切れたら、アドレスを手放して Discover からやり直します。',
      facts: [['T1', '43200 秒 (12 時間)'], ['送信元 → 宛先', `${LEASE} → ${SRV.ip} (ユニキャスト)`], ['ciaddr', LEASE]],
      state: { pc: `IP: ${LEASE} (延長)` },
      events: [
        ev('pc', 'srv', 'amber', 'DHCPREQUEST (更新)', (() => {
          const p = pkt(`DHCPREQUEST (更新): ${LEASE} を延長してください`, { note: 'Renew の Request にはオプション 50 (要求する IP) と 54 (サーバ ID) を入れない。アドレスは ciaddr に入っている。' });
          h.eth(p, { src: PC.mac, dst: SRV.mac, type: 0x0800, dstName: 'DHCP サーバ' });
          h.ipv4(p, { src: LEASE, dst: SRV.ip, proto: 17, ttl: 64, id: 0x0e31 });
          h.udp(p, { sport: 68, dport: 67, sname: 'bootpc', dname: 'bootps' });
          return dhcp(p, { op: 1, xid: XID2, ciaddr: LEASE, opts: [o.type(3), o.cid(), o.host(), o.prl(), o.end()] });
        })()),
        ev('srv', 'pc', 'teal', 'DHCPACK', (() => {
          const p = pkt('DHCPACK: さらに 24 時間どうぞ');
          h.eth(p, { src: SRV.mac, dst: PC.mac, type: 0x0800, srcName: 'DHCP サーバ' });
          h.ipv4(p, { src: SRV.ip, dst: LEASE, proto: 17, ttl: 64, id: 0x2c11 });
          h.udp(p, { sport: 67, dport: 68, sname: 'bootps', dname: 'bootpc' });
          return dhcp(p, { op: 2, xid: XID2, ciaddr: LEASE, yiaddr: LEASE, opts: serverOpts(5) });
        })()),
      ],
    },
  ],
  outro: {
    title: '叫んで、申し出を受けて、期限付きで借りる',
    text: 'DHCP は、アドレスを持たない PC がブロードキャストでサーバを探し (Discover)、申し出 (Offer) を受け入れ (Request)、確定 (Ack) をもらう 4 段階でした。借りたアドレスには期限があり、半分を過ぎると延長します。\n\nメッセージの前半は BOOTP、さらにその前の RARP の時代の欄を引きずっています。',
    points: [
      'ルータを越えた先の DHCP サーバを使うときは、ルータがリレーエージェントになって giaddr に LAN 側のアドレスを入れて中継する',
      '偽の DHCP サーバ (rogue DHCP) が先に答えると、PC は偽のゲートウェイや DNS を使ってしまう。スイッチの DHCP スヌーピングで防ぐ',
      'IPv6 ではアドレスは RA/SLAAC で自分で作ることが多く、DHCPv6 は「必要な場合だけ」使う',
      'Linux では journalctl や /var/lib/NetworkManager/*.lease でリースの中身を確認できる',
    ],
  },
});
})();
