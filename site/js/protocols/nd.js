// IPv6 近隣探索 (ND): アドレス解決、到達性の確認、重複の検出
'use strict';
(() => {
const { pkt, h, ev, local, ip6, mac } = PV;

const PC = { mac: '02:00:00:aa:00:10', ll: 'fe80::aa:10', ip: '2001:db8:1:1::10' };
const PCB = { mac: '02:00:00:bb:00:20', ip: '2001:db8:1:1::20' };
const NAS = { mac: '02:00:00:cc:00:50', ip: '2001:db8:1:1::50' };
const R = { mac: '02:00:5e:00:00:01', ll: 'fe80::1' };
const SOL = 'ff02::1:ff00:50', SOLMAC = '33:33:ff:00:00:50';

function icmp6(p, type, name, typeDesc) {
  return p.layer(`ICMPv6 ${name}`)
    .u8('タイプ', type, `${type} (${name})`, typeDesc)
    .u8('コード', 0, '0')
    .f('チェックサム', [0, 0], '', 'IPv6 の送信元・宛先を含む疑似ヘッダから計算', h.icmp6csum());
}
const lla = (p, type, m) => p
  .u8(type === 1 ? 'オプション: 送信元リンク層アドレス' : 'オプション: ターゲットリンク層アドレス', type,
    type === 1 ? '1 (Source Link-Layer Address)' : '2 (Target Link-Layer Address)',
    type === 1 ? '送った人の MAC アドレス。受け取った側はこれを覚えて、返事のために問い合わせ直さずに済む' : '答え: ターゲットアドレスの持ち主の MAC アドレス')
  .u8('  長さ', 1, '1 (= 8 バイト)', 'オプションの長さは 8 バイト単位', { depth: 1 })
  .f('  MAC アドレス', mac(m), m, undefined, { depth: 1 });
const ns = (p, target) => icmp6(p, 135, 'Neighbor Solicitation', '近隣要請。ARP 要求にあたる')
  .u32('予約', 0, '0')
  .f('ターゲットアドレス', ip6(target), target, '「このアドレスの人」');
function na(p, target, { r = 0, s, o }) {
  const flags = (r << 31 | s << 30 | o << 29) >>> 0;
  return icmp6(p, 136, 'Neighbor Advertisement', '近隣広告。ARP 応答にあたる')
    .u32('フラグ (R, S, O)', flags, `R=${r}, S=${s}, O=${o}`, 'R=送り主はルータ、S=要請への返事 (到達の確認になる)、O=相手のキャッシュを上書きしてよい')
    .f('ターゲットアドレス', ip6(target), target);
}

PV.register({
  id: 'nd', name: 'IPv6 ND', title: 'IPv6 の近隣探索 (ARP の代わり)', group: 'LAN の中', layerLabel: 'L3 · ICMPv6 タイプ 135/136',
  overview: {
    full: 'Neighbor Discovery Protocol (近隣探索)',
    description: 'IPv6 では ARP の代わりに、ICMPv6 の近隣要請 (NS) と近隣広告 (NA) で MAC アドレスを調べます。ブロードキャストは使わず、相手のアドレスから計算した「要請ノードマルチキャスト」宛てに尋ねるので、関係ない機器はネットワークカードの段階で読み捨てられます。さらに、相手がまだ生きているかの確認 (NUD) や、アドレスの重複検出 (DAD) も同じ仕組みで行います。',
    facts: [['層', 'ネットワーク層 (ICMPv6)'], ['NS の宛先', 'ff02::1:ffXX:XXXX (要請ノードマルチキャスト)'], ['ホップリミット', '255 固定'], ['IPv4 でいうと', 'ARP (+ ICMP リダイレクト)'], ['キャッシュの状態', 'INCOMPLETE → REACHABLE → STALE → DELAY → PROBE'], ['規格', 'RFC 4861']],
  },
  nodes: {
    pc: { label: 'PC', sub: PC.ip, x: 110, y: 110, icon: 'pc' },
    pcb: { label: '他の PC', sub: PCB.ip, x: 110, y: 300, icon: 'pc' },
    sw: { label: 'スイッチ', x: 380, y: 205, icon: 'relay' },
    nas: { label: 'NAS', sub: NAS.ip, x: 650, y: 110, icon: 'server' },
    router: { label: 'ルータ', sub: R.ll, x: 650, y: 300, icon: 'router' },
  },
  links: [['pc', 'sw'], ['pcb', 'sw'], ['sw', 'nas'], ['sw', 'router']],
  groups: [{ label: 'LAN 2001:db8:1:1::/64', x: 20, y: 30, w: 780, h: 340 }],
  lifelines: ['pc', 'pcb', 'nas', 'router'],
  legend: [['gray', '端末内の処理'], ['amber', '近隣要請 (NS)'], ['teal', '近隣広告 (NA)'], ['blue', '通常の通信']],
  steps: [
    {
      title: '宛先は同じ LAN の中',
      desc: `PC が NAS (${NAS.ip}) にファイルを送ろうとしています。宛先は同じプレフィックスなので、ルータを通さず直接届けます。`,
      detail: `直接届けるには NAS の MAC アドレスが必要ですが、近隣キャッシュ (IPv4 の ARP キャッシュにあたる) にはまだありません。エントリを INCOMPLETE (問い合わせ中) で作り、送りたいパケットは保留します。\n\n問い合わせ先は、NAS のアドレスの下位 24 ビット (00:00:50) を ff02::1:ff00:0/104 につなげた「要請ノードマルチキャストアドレス」${SOL} です。NAS は自分のアドレスに対応するこのグループを、起動時から聞いています。`,
      facts: [['宛先', `${NAS.ip} (同じ /64 → 直接届ける)`], ['要請ノードマルチキャスト', SOL], ['対応する MAC', SOLMAC]],
      state: { pc: `${NAS.ip}: INCOMPLETE` },
      events: [local('pc', '要請ノードマルチキャストを計算', `${NAS.ip} の下位 24 ビット = 00:0050\n→ ff02::1:ff + 00:0050 = ${SOL}\n→ MAC アドレスは 33:33 + IPv6 アドレスの下位 32 ビット = ${SOLMAC}`)],
    },
    {
      title: '近隣要請 (NS) で尋ねる',
      desc: `「${NAS.ip} の人、MAC アドレスを教えて」を要請ノードマルチキャストで送ります。`,
      detail: 'スイッチは (MLD スヌーピングをしていなければ) マルチキャストを全ポートに配ります。ここが ARP との違いで、他の PC のネットワークカードは「33:33:ff:00:00:50 のグループには入っていない」ので、OS に渡す前にハードウェアで捨てます。ブロードキャストと違って、無関係な機器の CPU を起こしません。\n\nNS には自分の MAC アドレス (送信元リンク層アドレス) を付けます。NAS はこれを覚えて、返事を送るときに問い合わせ直さずに済みます。',
      facts: [['宛先 IP', SOL], ['ホップリミット', '255 (LAN の外から送られた偽物を弾く)'], ['オプション', '送信元リンク層アドレス']],
      events: [
        ev('pc', ['pcb', 'nas', 'router'], 'amber', 'NS', (() => {
          const p = pkt(`近隣要請: ${NAS.ip} の MAC アドレスは？`);
          h.eth(p, { src: PC.mac, dst: SOLMAC, type: 0x86dd, dstName: '要請ノードマルチキャスト' });
          h.ipv6(p, { src: PC.ip, dst: SOL, next: 58, hlim: 255 });
          return lla(ns(p, NAS.ip), 1, PC.mac);
        })()),
        local('pcb', 'NIC が捨てる', `宛先 MAC ${SOLMAC} は自分が参加しているマルチキャストグループではないので、ネットワークカードが受信しない。OS は何も知らない。`),
        local('nas', '自分宛て → PC を覚える', `ターゲットが自分のアドレスなので応答する。送信元リンク層アドレスから ${PC.ip} = ${PC.mac} を近隣キャッシュに STALE で登録する。`),
      ],
    },
    {
      title: '近隣広告 (NA) で答える',
      desc: 'NAS が「それは私です。MAC アドレスはこれ」とユニキャストで答えます。',
      detail: 'NA のフラグ S (Solicited) = 1 は「あなたの要請への返事です」という意味で、これを受け取った PC は「相手に届くことを確認できた」としてエントリを REACHABLE にします。O (Override) = 1 は「キャッシュの古い値を上書きしてよい」。R (Router) = 0 なので NAS はルータではありません。\n\n保留していたパケットを送り出します。',
      facts: [['フラグ', 'R=0, S=1, O=1'], ['答え', `${NAS.ip} = ${NAS.mac}`]],
      state: { pc: `${NAS.ip}: REACHABLE` },
      events: [
        ev('nas', 'pc', 'teal', 'NA', (() => {
          const p = pkt(`近隣広告: ${NAS.ip} は ${NAS.mac} です`);
          h.eth(p, { src: NAS.mac, dst: PC.mac, type: 0x86dd, srcName: 'NAS' });
          h.ipv6(p, { src: NAS.ip, dst: PC.ip, next: 58, hlim: 255 });
          return lla(na(p, NAS.ip, { s: 1, o: 1 }), 2, NAS.mac);
        })()),
      ],
    },
    {
      title: 'しばらくして、まだ生きているか確かめる (NUD)',
      desc: 'REACHABLE は 30 秒ほどで STALE (古いかも) に変わります。STALE のまま送ると、少し待ってからユニキャストの NS で生存を確認します。',
      detail: 'ARP にはない、近隣到達性検出 (NUD) の仕組みです。\n\nSTALE のエントリ宛てにパケットを送ると、パケットはそのまま送りつつ DELAY 状態に入ります。5 秒以内に上位層から「届いている」証拠 (TCP の ACK など) が来なければ PROBE 状態になり、今度はマルチキャストではなく相手の MAC アドレス宛てに直接 NS を送ります。NA (S=1) が返れば REACHABLE に戻ります。返事がなければエントリを消し、パケットは「宛先に到達できない」になります。',
      facts: [['REACHABLE の時間', '約 30 秒 (15〜45 秒のランダム)'], ['DELAY', '5 秒'], ['PROBE の宛先', `${NAS.ip} (ユニキャスト)`]],
      state: { pc: `${NAS.ip}: REACHABLE (再確認)` },
      events: [
        local('pc', 'REACHABLE → STALE', '30 秒ほど経ったので、エントリを STALE にする。MAC アドレスは消さずに残しておく。'),
        ev('pc', 'nas', 'blue', 'データ (STALE のまま)', (() => {
          const p = pkt(`UDP データ → ${NAS.ip}`, { note: 'STALE でも MAC アドレスは分かっているので、待たずにそのまま送る。同時にエントリは DELAY になる。' });
          h.eth(p, { src: PC.mac, dst: NAS.mac, type: 0x86dd, dstName: 'NAS' });
          h.ipv6(p, { src: PC.ip, dst: NAS.ip, next: 17 });
          h.udp(p, { sport: 51515, dport: 9000 });
          return p.layer('データ').str('データ', 'backup-chunk-0001');
        })()),
        local('pc', 'DELAY → PROBE', '5 秒待っても上位層からの到達確認がないので PROBE に入り、相手に直接尋ねる。'),
        ev('pc', 'nas', 'amber', 'NS (NUD)', (() => {
          const p = pkt(`近隣要請 (到達確認): ${NAS.ip} さん、まだいますか？`, { note: '宛先がマルチキャストではなく相手のアドレスそのもの。MAC アドレスもキャッシュにある値を使う。' });
          h.eth(p, { src: PC.mac, dst: NAS.mac, type: 0x86dd, dstName: 'NAS' });
          h.ipv6(p, { src: PC.ip, dst: NAS.ip, next: 58, hlim: 255 });
          return ns(p, NAS.ip);
        })()),
        ev('nas', 'pc', 'teal', 'NA (S=1)', (() => {
          const p = pkt('近隣広告: います');
          h.eth(p, { src: NAS.mac, dst: PC.mac, type: 0x86dd, srcName: 'NAS' });
          h.ipv6(p, { src: NAS.ip, dst: PC.ip, next: 58, hlim: 255 });
          return lla(na(p, NAS.ip, { s: 1, o: 1 }), 2, NAS.mac);
        })()),
      ],
    },
    {
      title: 'アドレスの重複を防ぐ (DAD)',
      desc: `他の PC が、設定ミスで NAS と同じ ${NAS.ip} を使おうとしました。使い始める前の確認 (DAD) で、NAS が「使っています」と答えます。`,
      detail: 'DAD の NS は送信元が :: (未指定アドレス) です。まだ自分のアドレスとして名乗れないからです。\n\nNAS は自分のアドレスへの DAD を見つけると、NA を全ノード (ff02::1) 宛てに送ります。送信元が :: で返事の送り先が分からないためです。他の PC はこれを受け取り、アドレスを使わずに「重複 (duplicated)」として止めます。',
      facts: [['DAD の送信元', ':: (未指定)'], ['NA の宛先', 'ff02::1 (全ノード)'], ['NA のフラグ', 'S=0 (要請への返事ではない), O=1']],
      state: { pcb: `${NAS.ip}: 重複のため使用不可` },
      events: [
        ev('pcb', ['pc', 'nas', 'router'], 'amber', 'NS (DAD)', (() => {
          const p = pkt(`近隣要請 (DAD): ${NAS.ip} を使っている人はいますか？`);
          h.eth(p, { src: PCB.mac, dst: SOLMAC, type: 0x86dd, dstName: '要請ノードマルチキャスト' });
          h.ipv6(p, { src: '::', dst: SOL, next: 58, hlim: 255 });
          return ns(p, NAS.ip);
        })()),
        ev('nas', ['pc', 'pcb', 'router'], 'teal', 'NA (重複)', (() => {
          const p = pkt(`近隣広告: ${NAS.ip} は私が使っています`);
          h.eth(p, { src: NAS.mac, dst: '33:33:00:00:00:01', type: 0x86dd, srcName: 'NAS', dstName: '全ノード' });
          h.ipv6(p, { src: NAS.ip, dst: 'ff02::1', next: 58, hlim: 255 });
          return lla(na(p, NAS.ip, { s: 0, o: 1 }), 2, NAS.mac);
        })()),
        local('pcb', 'アドレスを使わない', `${NAS.ip} を「重複」とし、このアドレスでの通信を始めない (ip addr では dadfailed と表示される)。`),
      ],
    },
  ],
  outro: {
    title: 'ARP よりも静かで、確認も細かい',
    text: '近隣探索は、ARP と同じ「尋ねて本人が答える」仕組みを ICMPv6 の上で作り直したものです。要請ノードマルチキャストのおかげで無関係な機器を起こさず、NUD で相手がまだいるかを確かめ、DAD でアドレスの重複も防ぎます。\n\nルータ広告 (RA) やリダイレクトも同じ ICMPv6 の近隣探索の仲間です。',
    points: [
      'ホップリミット 255 の確認で、LAN の外から偽の NS/NA を送り込むことはできない。ただし LAN の中の偽装は ARP と同じく防げない (対策: RA Guard、ND スヌーピング、SEND)',
      'Linux では ip -6 neigh で近隣キャッシュと状態 (REACHABLE, STALE, …) を見られる',
      '要請ノードマルチキャストは下位 24 ビットで決まるので、::50 と ::1:0:0:50 は同じグループになる (それでも関係する機器はごく少ない)',
      'ARP と違い IP の上で動くので、IPsec で守る仕組み (SEND) も考えられたが、ほとんど使われていない',
    ],
  },
});
})();
