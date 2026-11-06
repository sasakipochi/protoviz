// NTP: 4 つのタイムスタンプから、時計のずれと往復の遅れを計算する
'use strict';
(() => {
const { pkt, h, ev, local, be, ip4, ascii } = PV;

const PC = '198.51.100.10', S2 = '203.0.113.123', S1 = '192.0.2.123';
const BASE = Date.UTC(2026, 10, 6, 3, 0, 0) * 1000; // マイクロ秒
// 時刻はすべてマイクロ秒の整数で持つ (浮動小数の誤差を避ける)
const PC_ERR = -123400;           // PC の時計は 0.1234 秒遅れている
const UP = 12000, DOWN = 18000;   // 行き 12 ms、帰り 18 ms (非対称)
const PROC = 400;                 // サーバ内の処理 0.4 ms
const t0 = BASE + 250000;         // 本当の時刻で、PC が送った瞬間
const T1 = t0 + PC_ERR;
const T2 = t0 + UP;
const T3 = T2 + PROC;
const T4 = T3 + DOWN + PC_ERR;
const OFFSET = ((T2 - T1) + (T3 - T4)) / 2;
const DELAY = (T4 - T1) - (T3 - T2);
// 上位 (stratum 1) とのやりとり
const U1 = BASE - 37000000, U2 = U1 + 4100, U3 = U2 + 30, U4 = U3 + 4300;

const fmt = (us) => {
  const d = new Date(Math.floor(us / 1000));
  return d.toISOString().slice(0, 19).replace('T', ' ') + '.' + String(((us % 1e6) + 1e6) % 1e6).padStart(6, '0') + ' UTC';
};
const ms = (us) => (us / 1000).toFixed(1) + ' ms';
// NTP のタイムスタンプ: 1900 年からの秒 (32 ビット) + 秒未満 (32 ビット、2^-32 秒単位)
function ts(us) {
  if (!us) return [0, 0, 0, 0, 0, 0, 0, 0];
  const sec = Math.floor(us / 1e6) + 2208988800;
  const frac = Math.round(((us % 1e6) * 2 ** 32) / 1e6);
  return [...be(sec, 4), ...be(frac, 4)];
}
const fixed16 = (sec) => be(Math.round(sec * 65536), 4);
const s8 = (n) => [n & 255];

function ntp(p, { li = 0, mode, stratum, poll = 6, prec, rdelay = 0, rdisp = 0, refid, refidVal, ref = 0, org = 0, rec = 0, xmt, notes = {} }) {
  const MODE = { 3: 'クライアント', 4: 'サーバ' };
  return p.layer(`NTP (${MODE[mode]})`)
    .u8('LI / バージョン / モード', (li << 6) | (4 << 3) | mode, `LI=${li}, v4, モード ${mode} (${MODE[mode]})`, 'LI: うるう秒の予告 (0=なし, 3=時計が未同期)。モード 3 が問い合わせ、4 が応答')
    .u8('ストラタム', stratum, stratum === 0 ? '0 (未指定)' : `${stratum}`, '基準時計から何段目か。1 = GPS や原子時計に直結、2 = stratum 1 に合わせたサーバ')
    .f('ポーリング間隔', s8(poll), `2^${poll} = ${2 ** poll} 秒`, '次に問い合わせるまでの間隔 (2 の何乗秒か)')
    .f('精度', s8(prec), `2^${prec} ≈ ${(2 ** prec * 1e6).toPrecision(2)} マイクロ秒`, '自分の時計の細かさ')
    .f('ルート遅延', fixed16(rdelay), `${(rdelay * 1000).toFixed(1)} ms`, '基準時計までの往復の遅れの合計 (16.16 固定小数点)')
    .f('ルート分散', fixed16(rdisp), `${(rdisp * 1000).toFixed(1)} ms`, '基準時計からの誤差の見積もり')
    .f('参照 ID', refid, refidVal, notes.refid || 'どの時計に合わせているか。stratum 1 なら基準の種類 (4 文字)、それ以外なら上位サーバの IPv4 アドレス')
    .f('参照タイムスタンプ', ts(ref), ref ? fmt(ref) : '0', '最後に上位と時刻を合わせた時刻')
    .f('発信タイムスタンプ (origin)', ts(org), org ? fmt(org) : '0', notes.org || '問い合わせの送信時刻をそのまま返す欄')
    .f('受信タイムスタンプ (receive)', ts(rec), rec ? fmt(rec) : '0', notes.rec || '問い合わせを受け取った時刻')
    .f('送信タイムスタンプ (transmit)', ts(xmt), fmt(xmt), notes.xmt || 'このパケットを送った時刻');
}
function wrap(src, dst, sport, dport, summary, build, note) {
  const p = pkt(summary, { note });
  h.ipv4(p, { src, dst, proto: 17, ttl: src === PC ? 64 : 57, id: (sport * 7) & 0xffff, df: true });
  h.udp(p, { sport, dport, sname: sport === 123 ? 'ntp' : undefined, dname: dport === 123 ? 'ntp' : undefined });
  return build(p);
}

PV.register({
  id: 'ntp', name: 'NTP', title: 'ネットワークで時計を合わせる', group: 'アプリケーション層', layerLabel: 'L7 · UDP 123',
  overview: {
    full: 'Network Time Protocol',
    description: '時計を合わせるには「今何時？」と聞くだけでは足りません。答えが届くまでの時間の分だけずれるからです。NTP は 1 往復で 4 つの時刻 (送った・受け取った・返した・受け取った) を集め、そこから「時計のずれ」と「往復の遅れ」を計算します。サーバは GPS や原子時計を頂点とした階層 (ストラタム) になっていて、遠い下の段でも数ミリ秒の精度で合わせられます。',
    facts: [['層', 'アプリケーション層 (UDP)'], ['ポート', '123'], ['パケット', '48 バイト固定 (拡張なしの場合)'], ['時刻の形', '1900 年からの秒 (32 ビット) + 秒未満 (32 ビット)'], ['暗号化', 'NTS (RFC 8915) で認証できる'], ['規格', 'RFC 5905']],
  },
  nodes: {
    pc: { label: 'PC (chrony)', sub: PC, x: 110, y: 205, icon: 'pc' },
    inet: { label: 'インターネット', x: 340, y: 205, icon: 'cloud' },
    s2: { label: 'stratum 2 サーバ', sub: S2, x: 580, y: 205, icon: 'server' },
    s1: { label: 'stratum 1 サーバ', sub: S1, x: 820, y: 205, icon: 'server' },
    gps: { label: 'GPS 衛星', sub: 'stratum 0 (基準時計)', x: 820, y: 60, icon: 'cloud' },
  },
  links: [['pc', 'inet'], ['inet', 's2'], ['s2', 's1'], ['s1', 'gps']],
  lifelines: ['pc', 's2', 's1'],
  legend: [['gray', '端末内の処理'], ['amber', '問い合わせ (モード 3)'], ['teal', '応答 (モード 4)']],
  steps: [
    {
      title: 'サーバも、上の段に合わせている',
      desc: 'NTP サーバは階層になっています。stratum 2 のサーバは、GPS 受信機を持つ stratum 1 のサーバに定期的に問い合わせて、自分の時計を合わせています。',
      detail: 'stratum 0 は GPS や原子時計などの基準時計そのもので、ネットワークにはつながっていません。それを直接つないだサーバが stratum 1、stratum 1 に合わせたサーバが stratum 2 … と 1 段ずつ増えます。上限は 15 で、16 は「同期していない」を表します。\n\nstratum 1 の応答の参照 ID は、基準の種類を表す 4 文字 ("GPS") です。',
      facts: [['stratum 0', 'GPS 衛星 (基準時計)'], ['stratum 1', `${S1} (参照 ID "GPS")`], ['stratum 2', `${S2} (参照 ID = ${S1})`]],
      state: { s1: 'GPS に同期', s2: 'stratum 1 に同期' },
      events: [
        ev('s2', 's1', 'amber', '問い合わせ', wrap(S2, S1, 123, 123, '時刻の問い合わせ (stratum 2 → stratum 1)', (p) =>
          ntp(p, { mode: 3, stratum: 2, poll: 10, prec: -24, rdelay: 0.0043, rdisp: 0.0118, refid: ip4(S1), refidVal: S1, ref: U1 - 1024000000, xmt: U1 }))),
        ev('s1', 's2', 'teal', '応答 (stratum 1)', wrap(S1, S2, 123, 123, '時刻の応答 (stratum 1, 基準は GPS)', (p) =>
          ntp(p, { mode: 4, stratum: 1, poll: 10, prec: -22, rdelay: 0, rdisp: 0.0002, refid: [...ascii('GPS'), 0], refidVal: '"GPS"', ref: U1 - 15000000, org: U1, rec: U2, xmt: U3, notes: { refid: 'stratum 1 なので、基準時計の種類を 4 文字で表す' } }))),
        local('s2', '自分の時計を調整', `往復 ${ms((U4 - U1) - (U3 - U2))} の相手と時刻を比べ、ずれを少しずつ直す。これを 1024 秒ごとに繰り返している。`),
      ],
    },
    {
      title: '問い合わせる (T1 を記録)',
      desc: 'PC は、自分の時計で「送った時刻 T1」を送信タイムスタンプに入れて、NTP サーバに問い合わせます。',
      detail: `PC の時計は実は 0.1234 秒遅れていますが、PC 自身はまだそれを知りません。\n\nT1 は PC の時計で ${fmt(T1)} です。chrony などの最近のクライアントは、ここに本当の時刻ではなく乱数を入れることがあります (送信時刻から PC を特定されないため)。サーバは中身を見ずにそのまま返してくるので、PC は手元に本当の T1 を覚えておけば計算できます。`,
      facts: [['T1 (PC の時計)', fmt(T1)], ['PC の時計の本当のずれ', '-0.1234 秒 (PC は知らない)']],
      state: { pc: '時計: 0.1234 秒遅れ' },
      events: [
        ev('pc', 's2', 'amber', '問い合わせ (T1)', wrap(PC, S2, 50123, 123, '時刻の問い合わせ: 今何時ですか？', (p) =>
          ntp(p, { mode: 3, stratum: 0, poll: 6, prec: -25, refid: [0, 0, 0, 0], refidVal: '0', xmt: T1, notes: { xmt: 'T1: PC が送った時刻 (PC の時計で)' } }),
          'クライアントの問い合わせは、ほとんどの欄が 0。中身として意味があるのは送信タイムスタンプ (T1) くらい。')),
      ],
    },
    {
      title: 'サーバが T2 と T3 を入れて返す',
      desc: 'サーバは受け取った時刻 T2 と、返す時刻 T3 を記録し、PC の T1 を「発信タイムスタンプ」欄にそのまま写して返します。',
      detail: `パケットは行きに ${ms(UP)}、帰りに ${ms(DOWN)} かかっています。行きと帰りで遅れが違う (非対称) ことに注意してください。NTP はこれを知ることができません。\n\n発信タイムスタンプが自分の送った T1 と一致するかで、PC は「自分の問い合わせへの本物の返事か」を確かめます (古いパケットや偽物を弾く)。`,
      facts: [['T2 (サーバが受け取った)', fmt(T2)], ['T3 (サーバが返した)', fmt(T3)], ['行き / 帰り (本当の値)', `${ms(UP)} / ${ms(DOWN)}`]],
      events: [
        ev('s2', 'pc', 'teal', '応答 (T1, T2, T3)', wrap(S2, PC, 123, 50123, '時刻の応答: T2 に受け取り、T3 に返しました', (p) =>
          ntp(p, { mode: 4, stratum: 2, poll: 6, prec: -24, rdelay: 0.0043, rdisp: 0.0121, refid: ip4(S1), refidVal: `${S1} (上位サーバ)`, ref: U4, org: T1, rec: T2, xmt: T3, notes: { org: 'T1: PC の問い合わせの送信タイムスタンプをそのまま写したもの', rec: 'T2: サーバが受け取った時刻', xmt: 'T3: サーバが返した時刻' } }))),
        local('pc', 'T4 を記録', `受け取った瞬間の自分の時計 T4 = ${fmt(T4)}`),
      ],
    },
    {
      title: '4 つの時刻から、ずれと遅れを計算する',
      desc: 'T1〜T4 がそろったので、時計のずれ (オフセット) と往復の遅れ (ディレイ) を計算します。',
      detail: `オフセット θ = ((T2 − T1) + (T3 − T4)) / 2\nディレイ δ = (T4 − T1) − (T3 − T2)\n\nT2 − T1 は「行きの遅れ + ずれ」、T3 − T4 は「ずれ − 帰りの遅れ」なので、足して 2 で割ると「行きと帰りが同じなら」遅れが打ち消されてずれだけが残ります。\n\n今回は θ = ${(OFFSET / 1e6).toFixed(4)} 秒と計算されました。本当のずれは 0.1234 秒なので、${((123400 - OFFSET) / 1000).toFixed(1)} ms の誤差があります。これは行き (12 ms) と帰り (18 ms) の差の半分で、NTP が原理的に消せない誤差です。誤差はディレイの半分 (${ms(DELAY / 2)}) を超えないことは保証されます。`,
      facts: [['T2 − T1', ms(T2 - T1)], ['T3 − T4', ms(T3 - T4)], ['オフセット θ', `+${(OFFSET / 1e6).toFixed(4)} 秒 (PC を進める)`], ['ディレイ δ', ms(DELAY)], ['本当のずれとの差', `${((123400 - OFFSET) / 1000).toFixed(1)} ms (= 非対称の半分)`]],
      events: [local('pc', 'θ と δ を計算', `T2 − T1 = ${ms(T2 - T1)}\nT3 − T4 = ${ms(T3 - T4)}\nθ = (${ms(T2 - T1)} + ${ms(T3 - T4)}) / 2 = ${ms(OFFSET)}\nδ = ${ms(T4 - T1)} − ${ms(T3 - T2)} = ${ms(DELAY)}`)],
    },
    {
      title: '時計を少しずつ直す',
      desc: 'ずれが分かっても、時計をいきなり 0.12 秒進めるとは限りません。少しずつ速く進めて追いつかせます (slew)。',
      detail: '時計が急に飛ぶと、ログの順番が逆転したり、タイマーが誤動作したりします。そこでずれが小さいときは、時計の進む速さを少しだけ変えて (例: 0.05% 速く) 数分〜数十分かけて追いつきます。起動直後などずれが大きいときは、一気に合わせます (step)。\n\n実際のクライアントは複数のサーバに何回も問い合わせ、ディレイが小さい (= 誤差の小さい) 結果を選び、明らかにおかしいサーバ (falseticker) を除外してから調整します。安定すると問い合わせの間隔を 64 秒から 1024 秒まで伸ばします。',
      facts: [['調整の方法', 'slew (少しずつ) / step (一気に)'], ['chrony の設定例', 'makestep 1 3 (1 秒以上ずれていれば、最初の 3 回だけ step)'], ['問い合わせ間隔', '64 秒 → 最大 1024 秒']],
      state: { pc: '時計: 同期済み (誤差 ≈ 3 ms)' },
      events: [local('pc', 'slew で調整', `+${ms(OFFSET)} を、時計の進む速さを少しだけ上げて数分かけて取り戻す。\n\nchronyc tracking で、今のずれ (System time) や速さの補正 (Frequency) を確認できる。`)],
    },
  ],
  outro: {
    title: '4 つの時刻で、遅れを打ち消す',
    text: 'NTP は 1 往復で T1〜T4 の 4 つの時刻を集め、「行きと帰りの遅れは同じ」と仮定して時計のずれを計算しました。非対称な経路では、その差の半分だけ誤差が残ります。\n\nサーバは基準時計を頂点とした階層になっていて、ストラタムが 1 つ増えるごとに少しずつ誤差が積み重なります。',
    points: [
      '普通の NTP は暗号も認証もないので、途中で時刻を書き換えられる。NTS (Network Time Security) は TLS で鍵を交換し、NTP パケットに認証タグを付ける',
      'うるう秒は LI ビットで予告される。Google などは 1 日かけて少しずつずらす (leap smear) 方式を使う',
      'サーバが「もう来ないで」と言うときは、ストラタム 0 + 参照 ID "RATE" などの Kiss-o\'-Death パケットを返す',
      'NTP のタイムスタンプは 2036 年に 32 ビットの秒があふれる (時代番号で区別する)',
      'もっと精度が必要な場合 (金融、通信基地局) は、ハードウェアでタイムスタンプを打つ PTP (IEEE 1588) を使う',
    ],
  },
});
})();
