// ARP: IPv4 アドレスから MAC アドレスを調べる
'use strict';
(() => {
const { pkt, h, ev, local } = PV;

const PC = { mac: '02:00:00:aa:00:10', ip: '192.0.2.10' };
const PCB = { mac: '02:00:00:bb:00:20', ip: '192.0.2.20' };
const GW = { mac: '02:00:5e:00:00:01', ip: '192.0.2.1' };
const BAD = { mac: '02:00:00:ee:66:66', ip: '192.0.2.66' };
const WEB = '203.0.113.80';
const BC = 'ff:ff:ff:ff:ff:ff', ZERO = '00:00:00:00:00:00';

function ping(reply) {
  const p = pkt(reply ? `ping の応答 (${WEB} から)` : `ping ${WEB}`, {
    note: reply ? undefined : 'IP の宛先は Web サーバ、Ethernet の宛先はルータの MAC アドレス。この MAC を知るために ARP をした。',
  });
  h.eth(p, reply ? { src: GW.mac, dst: PC.mac, type: 0x0800, srcName: 'ルータ' } : { src: PC.mac, dst: GW.mac, type: 0x0800, dstName: 'ルータ' });
  h.ipv4(p, reply ? { src: WEB, dst: PC.ip, proto: 1, ttl: 57, id: 0x5a21 } : { src: PC.ip, dst: WEB, proto: 1, id: 0x1c04 });
  p.layer(reply ? 'ICMP Echo Reply' : 'ICMP Echo Request')
    .u8('タイプ', reply ? 0 : 8, reply ? '0 (Echo Reply)' : '8 (Echo Request)')
    .u8('コード', 0, '0')
    .f('チェックサム', [0, 0], '', 'ICMP 全体から計算', h.icmp4csum())
    .u16('識別子', 0x2f01, '0x2f01').u16('シーケンス番号', 1, '1')
    .str('データ', 'protoviz-ping-0123456789abcdef');
  return p;
}

PV.register({
  id: 'arp', name: 'ARP', title: 'IP アドレスから MAC アドレスを調べる', group: 'LAN の中', layerLabel: 'L2/L3 の間 · EtherType 0x0806',
  overview: {
    full: 'Address Resolution Protocol',
    description: 'IPv4 で同じ LAN の相手にパケットを届けるには、相手の MAC アドレスが必要です。ARP は「この IP アドレスの人、MAC アドレスを教えて」と LAN 全体に叫び、本人が答える仕組みです。答えはしばらく ARP キャッシュに覚えておきます。認証の仕組みがないので、嘘の答えを信じてしまう弱点があります。',
    facts: [['層', 'IP の下 (Ethernet に直接載る)'], ['EtherType', '0x0806'], ['要求の宛先', 'ff:ff:ff:ff:ff:ff (ブロードキャスト)'], ['応答の宛先', '要求した人 (ユニキャスト)'], ['IPv6 では', 'ND (近隣探索) が代わりをする'], ['規格', 'RFC 826, RFC 5227']],
  },
  nodes: {
    pc: { label: 'PC', sub: PC.ip, x: 110, y: 110, icon: 'pc' },
    pcb: { label: '他の PC', sub: PCB.ip, x: 110, y: 280, icon: 'pc' },
    bad: { label: '悪意のある PC', sub: BAD.ip, x: 330, y: 300, icon: 'attacker' },
    sw: { label: 'スイッチ', x: 330, y: 190, icon: 'relay' },
    gw: { label: 'ルータ', sub: GW.ip, x: 560, y: 190, icon: 'router' },
    web: { label: 'Web サーバ', sub: WEB, x: 880, y: 190, icon: 'server' },
  },
  links: [['pc', 'sw'], ['pcb', 'sw'], ['bad', 'sw'], ['sw', 'gw'], ['gw', 'web']],
  groups: [{ label: 'LAN 192.0.2.0/24 (ブロードキャストが届く範囲)', x: 20, y: 30, w: 640, h: 345 }],
  height: 400,
  lifelines: ['pc', 'pcb', 'bad', 'gw', 'web'],
  legend: [['gray', '端末内の処理'], ['amber', 'ARP 要求 (ブロードキャスト)'], ['teal', 'ARP 応答'], ['blue', '通常の通信'], ['red', '偽の ARP']],
  steps: [
    {
      title: '次に渡す相手を決める',
      desc: 'PC が Web サーバに ping を送ろうとしています。まず「誰に渡せばよいか」を経路表で決めます。',
      detail: `宛先 ${WEB} は自分の LAN (192.0.2.0/24) の外なので、既定のゲートウェイ ${GW.ip} に渡します。\n\nIP パケットを Ethernet に載せるには、ゲートウェイの MAC アドレスが必要です。ARP キャッシュを見ましたが、まだ載っていません。`,
      facts: [['宛先', `${WEB} (LAN の外)`], ['次に渡す相手', `${GW.ip} (既定のゲートウェイ)`], ['ARP キャッシュ', '空']],
      state: { pc: 'ARP キャッシュ: 空' },
      events: [
        local('pc', '経路表を引く', `${WEB} → 192.0.2.0/24 には含まれない → 既定の経路 0.0.0.0/0 → 次の行き先 ${GW.ip}\n\nARP キャッシュに ${GW.ip} がないので、ping のパケットをいったん保留して ARP 要求を出す。`),
      ],
    },
    {
      title: 'LAN 全体に尋ねる (ARP 要求)',
      desc: `「${GW.ip} の人、MAC アドレスを教えて」を、LAN の全員に届くブロードキャストで送ります。`,
      detail: '宛先 MAC が ff:ff:ff:ff:ff:ff なので、スイッチは全ポートにコピーして配ります。ターゲット MAC はまだ分からないので 0 で埋めます。\n\n受け取った機器はターゲット IP を見て、自分でなければ捨てます。ルータは自分宛てなので、ついでに送信元 (PC) の IP と MAC を自分の ARP キャッシュに覚えます。こうしておくと、返事を送るときに PC へ ARP し直さずに済みます。',
      facts: [['宛先 MAC', BC], ['オペレーション', '1 (要求)'], ['ターゲット IP', GW.ip]],
      state: { pc: 'キャッシュ: 192.0.2.1 = 不完全', gw: `キャッシュ: ${PC.ip} を学習` },
      events: [
        ev('pc', ['pcb', 'bad', 'gw'], 'amber', 'ARP 要求', (() => {
          const p = pkt(`ARP 要求: ${GW.ip} の MAC アドレスは？ (${PC.ip} より)`);
          h.eth(p, { src: PC.mac, dst: BC, type: 0x0806, dstName: 'ブロードキャスト' });
          return h.arp(p, {
            op: 1, sha: PC.mac, spa: PC.ip, tha: ZERO, tpa: GW.ip,
            notes: { op: '1 = 要求', tha: 'まだ分からないので 0', tpa: '探している IP アドレス' },
          });
        })()),
        local('pcb', '自分宛てではない → 捨てる', `ターゲット IP が ${GW.ip} なので無視する。\n\nRFC 826 では、送信元 (${PC.ip}) がすでにキャッシュに載っていればその MAC を更新するが、新しく載せることはしない。`),
        local('gw', '自分宛て → 学習', `ターゲット IP が自分なので、送信元の ${PC.ip} = ${PC.mac} をキャッシュに登録してから応答を作る。`),
      ],
    },
    {
      title: '本人が答える (ARP 応答)',
      desc: 'ルータが「それは私です。MAC アドレスはこれ」と PC だけに返します。',
      detail: '応答はユニキャストなので、他の PC には届きません。PC はこれを ARP キャッシュに保存し、保留していた ping を送り出します。\n\nキャッシュはずっと残るわけではなく、Linux では使われなくなって数十秒〜数分で古い (STALE) 扱いになり、必要になったら確認し直します。',
      facts: [['オペレーション', '2 (応答)'], ['答え', `${GW.ip} = ${GW.mac}`]],
      state: { pc: `キャッシュ: ${GW.ip} = …00:01` },
      events: [
        ev('gw', 'pc', 'teal', 'ARP 応答', (() => {
          const p = pkt(`ARP 応答: ${GW.ip} は ${GW.mac} です`);
          h.eth(p, { src: GW.mac, dst: PC.mac, type: 0x0806, srcName: 'ルータ' });
          return h.arp(p, {
            op: 2, sha: GW.mac, spa: GW.ip, tha: PC.mac, tpa: PC.ip,
            notes: { op: '2 = 応答', sha: 'これが答え', tha: '要求してきた人' },
          });
        })()),
      ],
    },
    {
      title: 'やっと ping が送れる',
      desc: '保留していた ping を、ルータの MAC アドレス宛てに送ります。',
      detail: 'IP ヘッダの宛先は最後まで Web サーバのままです。Ethernet の宛先は「この区間で渡す相手」なので、区間ごとに変わります。ルータの先の区間では、ルータが同じように ARP (または他の方法) で次の相手を調べています。\n\n2回目以降はキャッシュに載っているので、ARP なしですぐに送れます。',
      facts: [['IP 宛先', WEB], ['MAC 宛先', `${GW.mac} (ルータ)`]],
      events: [
        ev('pc', 'web', 'blue', 'Echo Request', ping(false)),
        ev('web', 'pc', 'blue', 'Echo Reply', ping(true)),
      ],
    },
    {
      title: 'IP アドレスの重複を確かめる (ARP Probe / Announcement)',
      desc: '他の PC が起動しました。DHCP でもらった IP アドレスを使い始める前に、誰も使っていないかを ARP で確かめます。',
      detail: 'ARP Probe は送信元 IP を 0.0.0.0 にした ARP 要求です。まだ自分のアドレスとして名乗れないので 0 にします。返事が来たら「誰かが使っている」ので、そのアドレスは使いません (RFC 5227)。\n\n誰も答えなければ、ARP Announcement (送信元 IP とターゲット IP の両方を自分にした要求、いわゆる Gratuitous ARP) を流して「このアドレスは私が使います」と知らせます。古いキャッシュを持っている機器はこれで更新されます。',
      facts: [['Probe の送信元 IP', '0.0.0.0'], ['Announcement', '送信元 IP = ターゲット IP = 自分']],
      state: { pcb: `${PCB.ip} 使用開始` },
      events: [
        ev('pcb', ['pc', 'bad', 'gw'], 'amber', 'ARP Probe', (() => {
          const p = pkt(`ARP Probe: ${PCB.ip} を使っている人はいますか？`, { note: '送信元 IP が 0.0.0.0 なのが Probe の目印。受け取った側はこの要求で自分のキャッシュを更新しない。' });
          h.eth(p, { src: PCB.mac, dst: BC, type: 0x0806, dstName: 'ブロードキャスト' });
          return h.arp(p, { op: 1, sha: PCB.mac, spa: '0.0.0.0', tha: ZERO, tpa: PCB.ip, notes: { spa: 'まだ名乗れないので 0.0.0.0', tpa: 'これから使いたいアドレス' } });
        })()),
        local('pcb', '返事なし', '一定時間 (RFC 5227 では合計 1〜3 秒程度、Probe を 3 回) 待っても応答がないので、アドレスを使ってよいと判断する。'),
        ev('pcb', ['pc', 'bad', 'gw'], 'amber', 'Gratuitous ARP', (() => {
          const p = pkt(`ARP Announcement: ${PCB.ip} は ${PCB.mac} です`);
          h.eth(p, { src: PCB.mac, dst: BC, type: 0x0806, dstName: 'ブロードキャスト' });
          return h.arp(p, { op: 1, sha: PCB.mac, spa: PCB.ip, tha: ZERO, tpa: PCB.ip, notes: { spa: '自分', tpa: '自分。誰にも尋ねていない「告知」' } });
        })()),
      ],
    },
    {
      title: '嘘の答えを信じてしまう (ARP スプーフィング)',
      desc: 'ARP には「答えた人が本物か」を確かめる仕組みがありません。悪意のある PC が「ルータは私です」と送りつけると、PC はそれを信じてしまいます。',
      detail: `悪意のある PC が、頼まれてもいない ARP 応答を PC に送り続けます。中身は「${GW.ip} の MAC は ${BAD.mac}」。多くの OS は、キャッシュにある相手についての応答なら更新してしまいます。\n\nこれ以降、PC がインターネットに送るパケットはすべて悪意のある PC に届きます。悪意のある PC が本物のルータへ転送すれば、PC は気づかないまま通信を覗かれます (中間者攻撃)。\n\n対策はスイッチ側で行うのが基本です。DHCP スヌーピングで「どのポートに誰がいるか」を記録し、Dynamic ARP Inspection でそれと合わない ARP を捨てます。`,
      facts: [['偽の答え', `${GW.ip} = ${BAD.mac}`], ['結果', 'PC の外向きの通信が悪意のある PC を経由する'], ['対策', 'Dynamic ARP Inspection、静的 ARP、通信自体の暗号化 (TLS)']],
      state: { pc: `キャッシュ: ${GW.ip} = …66:66 ✗`, bad: '中間者' },
      events: [
        ev('bad', 'pc', 'red', '偽の ARP 応答', (() => {
          const p = pkt(`偽の ARP 応答: ${GW.ip} は ${BAD.mac} です`, { note: '送信元 IP はルータを名乗っているが、送信元 MAC は悪意のある PC のもの。ARP にはこれを見抜く方法がない。' });
          h.eth(p, { src: BAD.mac, dst: PC.mac, type: 0x0806, srcName: '悪意のある PC' });
          return h.arp(p, { op: 2, sha: BAD.mac, spa: GW.ip, tha: PC.mac, tpa: PC.ip, notes: { sha: '嘘: 自分の MAC', spa: '嘘: ルータの IP を名乗る' } });
        })()),
        local('pc', 'キャッシュを上書き', `${GW.ip} の MAC を ${BAD.mac} に書き換えてしまう。以降の外向きパケットは悪意のある PC へ。`),
      ],
    },
  ],
  outro: {
    title: '「叫んで、本人が答える」だけのシンプルな仕組み',
    text: 'ARP は、IP アドレスと MAC アドレスの対応をブロードキャストで尋ね、本人がユニキャストで答える仕組みでした。答えはキャッシュされ、アドレスの重複確認にも使われます。\n\nシンプルな分、誰の答えでも信じてしまいます。LAN の中に悪意のある機器がいる前提では、スイッチの機能や通信の暗号化で守る必要があります。',
    points: [
      'ARP 要求はブロードキャスト。機器が多い LAN では負担になるので、VLAN で区切る',
      'Gratuitous ARP は、冗長構成のルータ (VRRP) が切り替わったときに「新しい MAC はこちら」と知らせるのにも使われる',
      'Proxy ARP: ルータが他人の代わりに ARP に答え、別のネットワークの相手を同じ LAN にいるように見せる',
      'IPv6 では ARP がなくなり、ICMPv6 の近隣探索 (ND) がマルチキャストで同じことを行う',
    ],
  },
});
})();
