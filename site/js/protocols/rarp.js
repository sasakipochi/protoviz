// RARP: MAC アドレスから自分の IP アドレスを教えてもらう (DHCP 以前の方法)
'use strict';
(() => {
const { pkt, h, ev, local, ascii } = PV;

const WS = { mac: '08:00:20:1a:2b:3c', ip: '192.0.2.20' };
const SRV = { mac: '08:00:20:aa:bb:01', ip: '192.0.2.5' };
const OTHER = { mac: '02:00:00:cc:00:30', ip: '192.0.2.30' };
const BC = 'ff:ff:ff:ff:ff:ff';
const BOOTFILE = 'C0000214'; // 192.0.2.20 を 16 進にしたもの

PV.register({
  id: 'rarp', name: 'RARP', title: '自分の IP アドレスを教えてもらう (昔の方法)', group: 'LAN の中', layerLabel: 'L2/L3 の間 · EtherType 0x8035',
  overview: {
    full: 'Reverse Address Resolution Protocol',
    description: 'ARP の逆で、「私の MAC アドレスはこれです。私の IP アドレスは何ですか？」と尋ねるプロトコルです。1980 年代、ディスクを持たないワークステーションが起動するときに使われました。教えてもらえるのは IP アドレスだけで、ルータを越えられないため、BOOTP を経て DHCP に置き換わりました。今の LAN で見ることはまずありませんが、DHCP がなぜあの形をしているかが分かります。',
    facts: [['層', 'IP の下 (Ethernet に直接載る)'], ['EtherType', '0x8035 (ARP とは別番号)'], ['形式', 'ARP と同じ。オペレーションが 3 (要求), 4 (応答)'], ['分かること', 'IP アドレスだけ'], ['後継', 'BOOTP (1985) → DHCP (1993)'], ['規格', 'RFC 903 (1984)']],
  },
  nodes: {
    ws: { label: 'ディスクレス WS', sub: WS.mac, x: 130, y: 120, icon: 'pc' },
    other: { label: '他の機器', sub: OTHER.ip, x: 130, y: 300, icon: 'pc' },
    sw: { label: 'スイッチ', x: 420, y: 210, icon: 'relay' },
    srv: { label: 'RARP / ブートサーバ', sub: SRV.ip, x: 760, y: 210, icon: 'server' },
  },
  links: [['ws', 'sw'], ['other', 'sw'], ['sw', 'srv']],
  groups: [{ label: 'LAN 192.0.2.0/24', x: 30, y: 40, w: 900, h: 320 }],
  lifelines: ['ws', 'other', 'srv'],
  legend: [['gray', '端末内の処理'], ['amber', 'RARP 要求 (ブロードキャスト)'], ['teal', 'RARP 応答'], ['blue', 'TFTP']],
  steps: [
    {
      title: '電源を入れたが、自分の IP アドレスを知らない',
      desc: 'ディスクのないワークステーションは、IP アドレスの設定をどこにも保存していません。知っているのは、ネットワークカードに焼き込まれた MAC アドレスだけです。',
      detail: 'OS も設定もネットワーク上のサーバに置く運用 (ディスクレス・ワークステーション) では、起動用の ROM に入った小さなプログラムがまず自分の IP アドレスを知る必要があります。\n\nIP アドレスがないので IP の通信はできません。そこで IP を使わず、Ethernet に直接載る RARP で尋ねます。',
      facts: [['分かっていること', `自分の MAC アドレス ${WS.mac}`], ['分からないこと', 'IP アドレス、サーバの場所']],
      state: { ws: 'IP: なし' },
      events: [local('ws', 'ブート ROM が起動', 'ネットワークカードの MAC アドレスを読み、RARP 要求を組み立てる。IP スタックはまだ使えない。')],
    },
    {
      title: '「私の IP アドレスは？」(RARP 要求)',
      desc: 'LAN 全体にブロードキャストで尋ねます。中身は ARP とほぼ同じ形で、オペレーションが 3 になっています。',
      detail: 'ARP では「ターゲット IP」を埋めて「ターゲット MAC」を尋ねましたが、RARP は逆に「ターゲット MAC」(= 自分) を埋めて「ターゲット IP」を尋ねます。\n\nEtherType が ARP (0x0806) とは別の 0x8035 なので、RARP を知らない機器は中身を見ずに捨てます。',
      facts: [['EtherType', '0x8035'], ['オペレーション', '3 (RARP 要求)'], ['ターゲット MAC', `${WS.mac} (自分)`]],
      events: [
        ev('ws', ['other', 'srv'], 'amber', 'RARP 要求', (() => {
          const p = pkt('RARP 要求: MAC アドレス 08:00:20:1a:2b:3c の IP アドレスは？');
          h.eth(p, { src: WS.mac, dst: BC, type: 0x8035, dstName: 'ブロードキャスト' });
          return h.arp(p, {
            op: 3, sha: WS.mac, spa: '0.0.0.0', tha: WS.mac, tpa: '0.0.0.0',
            notes: { op: '3 = RARP 要求', spa: 'まだ分からない', tha: '「この MAC の人」= 自分', tpa: 'これを教えてほしい' },
          });
        })()),
        local('other', 'RARP を知らない → 捨てる', 'EtherType 0x8035 を扱うプログラムがないので、中身を見ずに破棄する。'),
      ],
    },
    {
      title: 'サーバが表を引いて答える (RARP 応答)',
      desc: 'RARP サーバは「MAC アドレス → IP アドレス」の対応表を持っています。表を引いて、見つかった IP アドレスを返します。',
      detail: `Unix の RARP サーバ (rarpd) は /etc/ethers で MAC アドレスからホスト名を、/etc/hosts でホスト名から IP アドレスを引きました。対応表は管理者が手で書きます。DHCP のように「空いているアドレスを自動で貸す」機能はありません。\n\n応答の送信元 IP にはサーバ自身のアドレスが入っています。ワークステーションはこれを「ブートサーバの場所」としても使いました。`,
      facts: [['/etc/ethers', `${WS.mac}  ws20`], ['/etc/hosts', `${WS.ip}  ws20`], ['答え', WS.ip]],
      state: { ws: `IP: ${WS.ip}` },
      events: [
        local('srv', '/etc/ethers を引く', `${WS.mac} → ws20 → ${WS.ip}\n\n表に載っていない MAC アドレスからの要求には何も答えない。`),
        ev('srv', 'ws', 'teal', 'RARP 応答', (() => {
          const p = pkt(`RARP 応答: あなたの IP アドレスは ${WS.ip} です`);
          h.eth(p, { src: SRV.mac, dst: WS.mac, type: 0x8035, srcName: 'RARP サーバ' });
          return h.arp(p, {
            op: 4, sha: SRV.mac, spa: SRV.ip, tha: WS.mac, tpa: WS.ip,
            notes: { op: '4 = RARP 応答', spa: 'サーバ自身。ブートサーバの場所としても使われた', tpa: '答え: あなたの IP アドレス' },
          });
        })()),
      ],
    },
    {
      title: 'OS を取りに行く (TFTP)',
      desc: 'IP アドレスが分かったので、やっと IP で通信できます。RARP サーバに TFTP で起動用のファイルを要求します。',
      detail: `Sun のワークステーションは、自分の IP アドレスを 16 進数にした名前 (${WS.ip} → ${BOOTFILE}) のファイルを要求しました。ファイル名も含めて、必要な情報を RARP の 1 往復からなんとか引き出す工夫です。\n\nTFTP の宛先 MAC は RARP 応答の送信元 MAC から分かるので、ここでは ARP も要りません。`,
      facts: [['プロトコル', 'TFTP (UDP 69)'], ['ファイル名', `${BOOTFILE} (自分の IP の 16 進表記)`]],
      events: [
        ev('ws', 'srv', 'blue', 'TFTP 読み出し要求', (() => {
          const p = pkt(`TFTP: ファイル ${BOOTFILE} をください`);
          h.eth(p, { src: WS.mac, dst: SRV.mac, type: 0x0800, dstName: 'ブートサーバ' });
          h.ipv4(p, { src: WS.ip, dst: SRV.ip, proto: 17, id: 1, df: false });
          h.udp(p, { sport: 1024, dport: 69, dname: 'tftp' });
          return p.layer('TFTP RRQ')
            .u16('オペコード', 1, '1 (RRQ: 読み出し要求)')
            .f('ファイル名', [...ascii(BOOTFILE), 0], JSON.stringify(BOOTFILE), '0 で終わる文字列')
            .f('モード', [...ascii('octet'), 0], '"octet"', 'バイナリのまま送る');
        })()),
        local('srv', 'ファイルを 512 バイトずつ送る', 'TFTP はデータを 512 バイトのブロックに分け、1 ブロックごとに確認応答を待つ単純な仕組み。ここから先は省略。'),
      ],
    },
    {
      title: 'なぜ使われなくなったのか',
      desc: 'RARP には大きな制約が 3 つありました。それを解決したのが BOOTP、さらにそれを発展させたのが DHCP です。',
      detail: '1. ルータを越えられない: Ethernet に直接載るので、LAN ごとに RARP サーバが必要でした。BOOTP は UDP に載せ、リレーエージェントで別の LAN のサーバに中継できるようにしました。\n\n2. IP アドレスしか分からない: サブネットマスク、ゲートウェイ、ブートファイル名などは別の方法で調べるしかありませんでした。BOOTP は 1 つの応答にまとめて入れました。\n\n3. 表を手で書く必要がある: DHCP はアドレスの範囲から自動で「貸し出す」(リース) 仕組みを加えました。',
      facts: [['RARP', 'L2 のみ・IP だけ・手書きの表'], ['BOOTP', 'UDP・リレー可・設定をまとめて返す'], ['DHCP', 'BOOTP + 自動貸し出し (リース) + オプション']],
      events: [local('ws', '振り返り', 'RARP で IP アドレス → TFTP で OS、という 2 段階の起動。今の PXE ブートは、DHCP で IP アドレスとブートファイル名を一度にもらい → TFTP/HTTP で取得、という同じ流れを受け継いでいる。')],
    },
  ],
  outro: {
    title: 'ARP を裏返しただけのプロトコル',
    text: 'RARP は ARP と同じ形のパケットで、MAC アドレスから IP アドレスを尋ねました。仕組みは単純ですが、ルータを越えられず、IP アドレス以外の情報も渡せませんでした。\n\nDHCP のメッセージに今も「クライアントのハードウェアアドレス」や「サーバ名」「ブートファイル名」の欄があるのは、この時代の流れを受け継いでいるからです。',
    points: [
      'ARP と RARP は形が同じで、EtherType とオペレーションの番号だけが違う',
      'RARP サーバは LAN ごとに必要だった。BOOTP/DHCP のリレーエージェントはこの問題を解決した',
      '仮想化の世界では今も使われることがある: VMware などは VM の移動後に RARP を流して、スイッチに新しい場所を覚えさせる',
    ],
  },
});
})();
