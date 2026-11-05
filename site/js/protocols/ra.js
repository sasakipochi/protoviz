// IPv6 ルータ広告 (RA) と SLAAC によるアドレス自動設定
'use strict';
(() => {
const { pkt, h, ev, local, ip6, mac } = PV;

const R_MAC = '02:00:5e:10:00:01', R_LL = 'fe80::1';
const PC_MAC = '02:1a:2b:3c:4d:5e';
const PC_LL = 'fe80::3c1a:9f2e:77b4:c51';
const PC_GUA = '2001:db8:1234:5678:8d2f:61e0:5a3b:9c17';
const PREFIX = '2001:db8:1234:5678::';
const WEB = '2001:db8:ffff::80';

function icmp6(p, type, code, name, typeDesc) {
  return p.layer(`ICMPv6 ${name}`)
    .u8('タイプ', type, `${type} (${name})`, typeDesc)
    .u8('コード', code, String(code))
    .f('チェックサム', [0, 0], '', 'IPv6 の送信元・宛先を含む疑似ヘッダから計算', h.icmp6csum());
}
const slla = (p, m, name = '送信元リンク層アドレス') => p
  .u8(`オプション: ${name}`, 1, '1 (Source Link-Layer Address)', '「自分の MAC アドレスはこれ」というオプション。受け取った側は ARP にあたる問い合わせをせずに済む')
  .u8('  長さ', 1, '1 (= 8 バイト)', 'オプションの長さは 8 バイト単位', { depth: 1 })
  .f('  MAC アドレス', mac(m), m, undefined, { depth: 1 });

function dadNS(target, sol, solMac, seed) {
  const p = pkt(`近隣要請 (DAD): ${target} を使っている人はいますか？`, {
    note: '送信元が :: (未指定アドレス) なのが DAD の目印。まだ自分のアドレスが確定していないので名乗れない。',
  });
  h.eth(p, { src: PC_MAC, dst: solMac, type: 0x86dd, dstName: '要請ノードマルチキャスト' });
  h.ipv6(p, { src: '::', dst: sol, next: 58, hlim: 255 });
  icmp6(p, 135, 0, 'Neighbor Solicitation', '近隣要請。IPv4 の ARP 要求にあたる')
    .u32('予約', 0, '0')
    .f('ターゲットアドレス', ip6(target), target, '使おうとしているアドレス。誰かが使っていれば Neighbor Advertisement で反論してくる');
  return p;
}

PV.register({
  id: 'ra', name: 'IPv6 RA / SLAAC', title: 'IPv6 アドレスの自動設定', group: 'ネットワーク層', layerLabel: 'L3 · ICMPv6 / NDP',
  overview: {
    full: 'Router Advertisement と SLAAC (ステートレスアドレス自動設定)',
    description: 'IPv6 では、LAN につないだ PC がルータからの「広告 (RA)」を聞いて、自分でアドレスを組み立てます。DHCP サーバがなくても、プレフィックス (アドレスの前半 64 ビット) と既定のゲートウェイ、DNS サーバが分かる仕組みです。RA は ICMPv6 の一種で、近隣探索プロトコル (NDP) の一部です。',
    facts: [['層', 'ネットワーク層 (ICMPv6)'], ['宛先', 'ff02::1 (全ノード), ff02::2 (全ルータ)'], ['送信元', 'ルータのリンクローカルアドレス'], ['ホップリミット', '255 固定'], ['IPv4 でいうと', 'ARP + DHCP + デフォルトゲートウェイ'], ['規格', 'RFC 4861, RFC 4862, RFC 8106']],
  },
  nodes: {
    pc: { label: 'PC', sub: PC_MAC, x: 110, y: 120, icon: 'pc' },
    pcb: { label: '他の PC', sub: '同じ LAN', x: 110, y: 290, icon: 'pc' },
    sw: { label: 'スイッチ', x: 310, y: 205, icon: 'relay' },
    router: { label: 'ルータ', sub: R_LL, x: 520, y: 205, icon: 'router' },
    inet: { label: 'インターネット', x: 730, y: 205, icon: 'cloud' },
    web: { label: 'Web サーバ', sub: WEB, x: 910, y: 205, icon: 'server' },
  },
  links: [['pc', 'sw'], ['pcb', 'sw'], ['sw', 'router'], ['router', 'inet'], ['inet', 'web']],
  groups: [{ label: 'LAN (1つのリンク = マルチキャストが届く範囲)', x: 20, y: 40, w: 600, h: 320 }],
  lifelines: ['pc', 'pcb', 'router', 'web'],
  legend: [['gray', '端末内の処理'], ['teal', '近隣要請 (NS)'], ['amber', 'ルータ要請 (RS)'], ['violet', 'ルータ広告 (RA)'], ['blue', '通常の通信']],
  steps: [
    {
      title: 'リンクローカルアドレスを作る',
      desc: 'LAN につながった瞬間、PC はまず「この LAN の中だけで使えるアドレス」を自分で作ります。',
      detail: 'fe80:: で始まるリンクローカルアドレスは、ルータを越えられない代わりに誰の許可もなく使えます。後半 64 ビット (インターフェース ID) は、昔は MAC アドレスから作っていましたが (EUI-64)、今の OS はプライバシーのため乱数やハッシュで作ります。\n\n本当に使ってよいか、同じアドレスの人がいないかを確かめる DAD (重複アドレス検出) を行います。返事がなければ使用開始です。',
      facts: [['作ったアドレス', PC_LL], ['DAD の宛先', 'ff02::1:ffb4:c51 (要請ノードマルチキャスト)']],
      state: { pc: 'fe80::… (仮)' },
      events: [
        local('pc', 'fe80:: アドレスを生成', `プレフィックス fe80::/64 に、自分で決めたインターフェース ID 3c1a:9f2e:77b4:0c51 をつなげて ${PC_LL} を作る。\n\nこの段階ではまだ「仮 (tentative)」で、DAD が終わるまで通信には使わない。`),
        ev('pc', ['pcb', 'router'], 'teal', 'NS (DAD)', dadNS(PC_LL, 'ff02::1:ffb4:c51', '33:33:ff:b4:0c:51', 'dad1')),
        local('pc', '返事なし → 使用開始', '約1秒待っても Neighbor Advertisement が返ってこなかったので、同じアドレスを使っている人はいないと判断し、アドレスを確定する。'),
      ],
    },
    {
      title: 'ルータを探す (RS)',
      desc: 'PC は「この LAN にルータはいますか？」と全ルータ宛てのマルチキャストで尋ねます。',
      detail: 'ルータは数分おきに RA を自分から送っていますが、待っていると時間がかかるので、PC は起動直後にルータ要請 (Router Solicitation) を送って RA を催促します。\n\n宛先 ff02::2 は「このリンク上のすべてのルータ」を表すマルチキャストアドレスです。Ethernet の宛先 MAC は 33:33 + IPv6 アドレスの下位 32 ビットになります。',
      facts: [['送信元', PC_LL], ['宛先', 'ff02::2 (全ルータ)'], ['宛先 MAC', '33:33:00:00:00:02']],
      state: { pc: 'fe80::3c1a:… のみ' },
      events: [
        ev('pc', 'router', 'amber', 'RS', (() => {
          const p = pkt('ルータ要請: ルータはいますか？');
          h.eth(p, { src: PC_MAC, dst: '33:33:00:00:00:02', type: 0x86dd, dstName: '全ルータ' });
          h.ipv6(p, { src: PC_LL, dst: 'ff02::2', next: 58, hlim: 255 });
          icmp6(p, 133, 0, 'Router Solicitation', 'ルータ要請。「RA を今すぐ送って」の合図').u32('予約', 0, '0');
          return slla(p, PC_MAC);
        })()),
      ],
    },
    {
      title: 'ルータが広告する (RA)',
      desc: 'ルータが LAN の全員に向けて「私がルータです。プレフィックスはこれ、DNS はこれ」と知らせます。',
      detail: 'RA には、既定のゲートウェイとして使ってよい期間 (ルータ寿命)、プレフィックス情報、MTU、DNS サーバ (RDNSS) などが入っています。送信元がルータのリンクローカルアドレスなので、PC は既定のゲートウェイを fe80::1 として覚えます。\n\nM フラグ・O フラグは「アドレスは DHCPv6 でもらって」「その他の情報は DHCPv6 で」という指示です。ここでは両方 0 なので、DHCPv6 は使いません。',
      facts: [['プレフィックス', '2001:db8:1234:5678::/64'], ['フラグ', 'M=0 O=0 (DHCPv6 なし)'], ['ルータ寿命', '1800 秒'], ['DNS (RDNSS)', '2001:db8:1234:5678::1']],
      state: { router: 'RA 送信', pcb: 'RA 受信' },
      events: [
        ev('router', ['pc', 'pcb'], 'violet', 'RA', (() => {
          const p = pkt('ルータ広告: プレフィックス 2001:db8:1234:5678::/64', {
            note: 'ホップリミットが 255 であることを受信側は必ず確認する。ルータを1つでも越えると 254 以下になるので、LAN の外から偽の RA を送り込むことはできない。',
          });
          h.eth(p, { src: R_MAC, dst: '33:33:00:00:00:01', type: 0x86dd, dstName: '全ノード', srcName: 'ルータ' });
          h.ipv6(p, { src: R_LL, dst: 'ff02::1', next: 58, hlim: 255 });
          icmp6(p, 134, 0, 'Router Advertisement', 'ルータ広告')
            .u8('推奨ホップリミット', 64, '64', '端末が送るパケットのホップリミットの初期値')
            .u8('フラグ (M, O, …)', 0x00, 'M=0, O=0', 'M=1 ならアドレスは DHCPv6 で取得、O=1 なら DNS などの情報だけ DHCPv6 で取得')
            .u16('ルータ寿命', 1800, '1800 秒', 'この期間、私を既定のゲートウェイとして使ってよい。0 ならゲートウェイにしないで、の意味')
            .u32('到達可能時間', 0, '0 (指定なし)')
            .u32('再送間隔', 0, '0 (指定なし)');
          slla(p, R_MAC);
          p.u8('オプション: MTU', 5, '5 (MTU)', 'このリンクの MTU')
            .u8('  長さ', 1, '1 (= 8 バイト)', undefined, { depth: 1 })
            .u16('  予約', 0, '0', undefined, { depth: 1 })
            .u32('  MTU', 1500, '1500', undefined, { depth: 1 })
            .u8('オプション: プレフィックス情報', 3, '3 (Prefix Information)', 'SLAAC の材料になる一番大事なオプション')
            .u8('  長さ', 4, '4 (= 32 バイト)', undefined, { depth: 1 })
            .u8('  プレフィックス長', 64, '64', 'SLAAC は /64 のときだけ動く', { depth: 1 })
            .u8('  フラグ (L, A)', 0xc0, 'L=1, A=1', 'L=このプレフィックスは同じリンク上にある (直接届く)、A=これを使ってアドレスを自動生成してよい', { depth: 1 })
            .u32('  有効期間', 2592000, '2592000 秒 (30 日)', 'この期間を過ぎたアドレスは使えなくなる', { depth: 1 })
            .u32('  推奨期間', 604800, '604800 秒 (7 日)', 'この期間を過ぎると新しい通信には使わなくなる (古い通信は続けられる)', { depth: 1 })
            .u32('  予約', 0, '0', undefined, { depth: 1 })
            .f('  プレフィックス', ip6(PREFIX), '2001:db8:1234:5678::', undefined, { depth: 1 })
            .u8('オプション: DNS サーバ', 25, '25 (RDNSS)', 'RFC 8106。これのおかげで DHCPv6 なしで DNS サーバが分かる')
            .u8('  長さ', 3, '3 (= 24 バイト)', undefined, { depth: 1 })
            .u16('  予約', 0, '0', undefined, { depth: 1 })
            .u32('  有効期間', 1800, '1800 秒', undefined, { depth: 1 })
            .f('  DNS サーバ', ip6('2001:db8:1234:5678::1'), '2001:db8:1234:5678::1', undefined, { depth: 1 });
          return p;
        })()),
      ],
    },
    {
      title: 'アドレスを組み立てる (SLAAC)',
      desc: 'PC は受け取ったプレフィックスに自分で決めた後半 64 ビットをつなげて、グローバルアドレスを作ります。',
      detail: '前半 64 ビットはルータから、後半 64 ビットは自分で。これがステートレスアドレス自動設定 (SLAAC) です。ルータは誰にどのアドレスを渡したかを記録しません (だから「ステートレス」)。\n\n多くの OS は、ずっと同じ値を使う安定アドレス (RFC 7217) に加えて、外向きの通信用に数時間〜1日で入れ替わる一時アドレス (RFC 8981) も作ります。追跡されにくくするためです。\n\n新しいアドレスにも DAD を行います。',
      facts: [['グローバルアドレス', PC_GUA], ['既定のゲートウェイ', 'fe80::1 (RA の送信元)'], ['DNS', '2001:db8:1234:5678::1']],
      state: { pc: '2001:db8:…:9c17 ✓', pcb: '自分のアドレスも生成' },
      events: [
        local('pc', 'プレフィックス + ID', `2001:db8:1234:5678 (RA から) + 8d2f:61e0:5a3b:9c17 (自分で生成) = ${PC_GUA}\n\nあわせて、既定の経路 (::/0) の次の行き先を fe80::1 に、DNS サーバを 2001:db8:1234:5678::1 に設定する。`),
        ev('pc', ['pcb', 'router'], 'teal', 'NS (DAD)', dadNS(PC_GUA, 'ff02::1:ff3b:9c17', '33:33:ff:3b:9c:17', 'dad2')),
        local('pc', 'グローバルアドレス確定', '返事がないのでアドレスを確定。インターネットと通信できる状態になった。'),
      ],
    },
    {
      title: 'インターネットと通信する',
      desc: 'LAN の外宛てのパケットは、RA で知ったルータに渡します。',
      detail: '宛先の Web サーバは LAN の外なので、パケットの IP 宛先は Web サーバ、Ethernet の宛先 MAC はルータです。ルータの MAC アドレスは RA の「送信元リンク層アドレス」オプションで分かっているので、問い合わせ (NS) なしでいきなり送れます。\n\nここでは疎通確認の ping (ICMPv6 エコー要求) を送っています。',
      facts: [['IP 宛先', WEB], ['MAC 宛先', `${R_MAC} (ルータ)`]],
      events: [
        ev('pc', 'web', 'blue', 'Echo Request', (() => {
          const p = pkt(`ping ${WEB}`, { note: 'LAN 上で見たパケット。IP の宛先は Web サーバだが、Ethernet の宛先はルータになっている点に注目。' });
          h.eth(p, { src: PC_MAC, dst: R_MAC, type: 0x86dd, dstName: 'ルータ' });
          h.ipv6(p, { src: PC_GUA, dst: WEB, next: 58, hlim: 64 });
          icmp6(p, 128, 0, 'Echo Request', 'ping の要求')
            .u16('識別子', 0x1d2c, '0x1d2c').u16('シーケンス番号', 1, '1')
            .str('データ', 'protoviz-ping-0123456789abcdef');
          return p;
        })()),
        ev('web', 'pc', 'blue', 'Echo Reply', (() => {
          const p = pkt(`ping の応答 (${WEB} から)`);
          h.eth(p, { src: R_MAC, dst: PC_MAC, type: 0x86dd, srcName: 'ルータ' });
          h.ipv6(p, { src: WEB, dst: PC_GUA, next: 58, hlim: 58 });
          icmp6(p, 129, 0, 'Echo Reply', 'ping の応答')
            .u16('識別子', 0x1d2c, '0x1d2c').u16('シーケンス番号', 1, '1')
            .str('データ', 'protoviz-ping-0123456789abcdef');
          return p;
        })()),
      ],
    },
  ],
  outro: {
    title: 'DHCP サーバなしで、つないだだけで通信できた',
    text: 'IPv6 の端末は、リンクローカルアドレスを自分で作り、ルータ広告からプレフィックス・ゲートウェイ・DNS を学び、後半を自分で決めてグローバルアドレスを作りました。ルータは配ったアドレスを覚えていません。\n\nこの仕組みは「LAN の中の誰の RA でも信じてしまう」という弱点も持っています。',
    points: [
      '偽の RA (rogue RA): LAN 内の誰かが RA を送ると、PC はそちらをゲートウェイにしてしまう。スイッチの RA Guard で防ぐ',
      'ルータ寿命 0 の RA を送ると「もうゲートウェイにしないで」の意味になる (ルータの切り替えに使う)',
      'M=1 なら DHCPv6 でアドレスを取る。Android は DHCPv6 のアドレス取得に対応していないため、SLAAC が必須の現場が多い',
      'ホップリミット 255 の確認により、LAN の外からは RA を送り込めない',
    ],
  },
});
})();
