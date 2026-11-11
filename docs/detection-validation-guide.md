# 検知検証ガイド（どのやり方で・どの資料を見るか）

本命5検知（#1 監査無効化 / #3 アーカイブ収集 / #4 不審タスク / #5 ランサムノート / #6 AdminSDHolder）を
正検知として出す方法は **2通り**ある。目的で使い分ける。このメモは「どっちを・どの資料で進めるか」の道案内。

---

## 2つのやり方

| | パスA：手動 PowerShell | パスB：Caldera 通し実行 |
|---|---|---|
| **何をするか** | 各ルールのログを 1本ずつ PowerShell で直接生成 | 1オペレーションでキルチェーンを通しで流す |
| **プロセスの親** | `explorer → powershell`（人が叩いた形） | `splunkd.exe`（インプラント配下＝非対話） |
| **向く目的** | 「ルールが技術的に当たるか」を最速で確認 | 「攻撃としての説得力」を作る・レポート練習 |
| **実行単位** | ルール単位（1本ずつ独立、前後でリセット） | インシデント単位（5検知が1相関に束なる） |
| **見る資料** | **`docs/escu-validation-story-01.md`** | **`docs/caldera-killchain-run.md`** |
| **設計の読み物** | 同上（ストーリー込み） | **`docs/attack-killchain-story-02.md`**（設計背景） |

> 両者は排他ではない。**まずパスAで1本ずつ発火を確定**させ、**次にパスBで一連の流れとして正検知レポートを作る**、が実務の順番。
> パスA＝技術的に当たるかの確認、パスB＝攻撃としての説得力、という役割分担（story-02 冒頭の「使い分け」と同じ）。

---

## パスA：手動 PowerShell で 1本ずつ

- **資料**：`docs/escu-validation-story-01.md`
- **中身**：5検知（＋Palo の#2）ごとに「検知の急所 / 手順（PowerShell）/ 生ログ確認 SPL / 元に戻す」がセットで並ぶ。
- **使うとき**：ルールを有効化した直後、「このルール、ちゃんとログで当たる？」を素早く潰したいとき。
- **注意**：各テストは独立に実行し、前後で監査などをリセットする（story-01 の各手順に「戻す」付き）。
  特に #1（監査無効化）と #6（5136）は順番を誤ると潰し合うので、1本ずつが安全。

## パスB：Caldera で通し実行

- **手順書**：`docs/caldera-killchain-run.md`（配置 → 1オペ実行 → 検知マッピング → タイムライン束ね → 個別トリアージ → 後片付け）
- **設計背景**：`docs/attack-killchain-story-02.md`（なぜ親を splunkd にするか、キルチェーンの筋、トリアージカード）
- **設定ファイル**：
  - `caldera/abilities/aar-killchain/` … 5検知のアビリティ（ホストガード＋cleanup 付き）
  - `caldera/adversaries/killchain-01.yml` … 通しで流すアドバーサリ
- **使うとき**：パスAで各ルールが当たると確認できた後、「1つの侵入として一連で起きた」正検知レポートを作るとき。
- **エージェント名を変える場合**：`caldera-killchain-run.md` の「補足：検索インベントリ」を見る（直す SPL は2本だけ）。

---

## 共通の前提（どちらでも要る）

- **ルール選定**：`docs/escu-selection.md`（本命の選定理由・ラボ固有の穴）
- **tstats 系が 0 件になる罠**：`docs/troubleshooting-escu-tstats.md`（CIM アクセラレーション/index マクロ）
- **事前設定**（主に #1 #6）：ルール #1 の `host=ar-dc` クローン、#6 の「Directory Service Changes 監査＋AdminSDHolder の SACL＋labuser1」。
  詳細は `escu-validation-story-01.md` の各ルール節。destroy→再build したら消えている可能性があるので都度確認。

---

## 早見まとめ

- **とにかく当たるか確認したい** → パスA → `docs/escu-validation-story-01.md`
- **レポート用に一連の流れで出したい** → パスB → `docs/caldera-killchain-run.md`（設計は `attack-killchain-story-02.md`）
- **どのルールを・なぜ選んだか** → `docs/escu-selection.md`
- **ログが届くのに検知が 0 件** → `docs/troubleshooting-escu-tstats.md`
