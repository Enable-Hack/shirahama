# shirahama — 情報危機管理コンテスト 白浜 whiskey 班

> ⚠️ Private repo（チーム限定）。機密情報を含む。public 化禁止。

セキュリティ・キャンプ 2026 ミニ B トラックで学んだ AI ログ分析パイプライン（観測→判断→検証→提案）を、白浜の **電話受電起点で複数攻撃カテゴリに対応する半自動インシデント対応** に応用する作業ディレクトリ。

## ディレクトリ構成

```
shirahama/
├── README.md                              ← このファイル
├── .gitignore                             ← .env / *.log / 機密を除外
│
├── 00_目次.md 〜 17_本番前タスクリスト.md  ← 既存 playbook 群
├── 18_キャンプ知見の白浜活用方針.md         ← 全体方針 (作成済)
├── 19_AIパイプライン実装ガイド.md           ← 実装ガイド (今後作成)
│
├── agent/                                 ← キャンプ ai-agent コード（核）
│   ├── analyzer.py                        ← 観測層: パターン検出
│   ├── llm.py                             ← 型定義 (LLMBackend / Signal / PatchProposal)
│   ├── validator.py                       ← 検証層: 壊れた提案を弾く
│   ├── patcher.py                         ← 統合オーケストレータ
│   ├── prompts.py                         ← Claude/Swallow 用 system prompt
│   ├── backends/
│   │   ├── mock_backend.py                ← 判断層: 決定論的
│   │   ├── claude_backend.py              ← 判断層: Claude API
│   │   └── swallow_backend.py             ← 使わない（速度優先で切捨て）
│   └── renderers/                         ← 使わない (Claude が直接コマンド出力)
│
├── scripts/                               ← 前処理・自動化スクリプト
│   ├── preprocess/                        ← テキストログ → JSONL
│   │   ├── _common.py                     ← emit() / stream_lines() 共通
│   │   ├── parse_clf.py                   ← Apache CLF
│   │   ├── parse_secure.py                ← /var/log/secure
│   │   ├── parse_maillog.py               ← postfix/sendmail
│   │   ├── parse_named.py                 ← BIND
│   │   └── parse_syslog.py                ← 汎用 syslog
│   ├── feed/                              ← Loop1 (CVE feed)
│   │   ├── fetch_cve.py                   ← CISA KEV から取得
│   │   └── run_daily.sh                   ← 毎日実行
│   └── run_analyzer.sh                    ← 一気通貫実行
│
├── .claude/commands/                      ← Claude Code slash commands
│   ├── incident.md                        ← 汎用エントリ /incident
│   ├── wp-tamper.md                       ← /wp-tamper
│   ├── dns-tamper.md                      ← /dns-tamper
│   ├── ddos.md                            ← /ddos
│   ├── phishing.md                        ← /phishing
│   └── ransomware.md                      ← /ransomware
│
├── reference/                             ← 参考コード（白浜本体では使わない）
│   ├── README.md
│   └── dns2_main.rs                       ← Rust DNS サーバー（JSONL 流儀の参考）
│
└── data/cve/                              ← CVE feed のキャッシュ（gitignore）
```

## 設計の核

```
[電話受電] → 01_受電シート (時間窓・ホストのみ)
   ↓
/incident 13:00-13:30 victor
   ↓
preprocess (テキスト → JSONL)
   ↓
analyzer (パターン検出 + Loop1 動的 CVE)
   ↓
Mock 第1段 (whitelist drop)
Mock 第2段 (known-bad 即出し)
grey → Claude API (集約・推奨手順生成)
   ↓
validator (壊れた提案を棄却)
   ↓
[人間レビュー = リーダー Go/NoGo]
   ↓
カテゴリ別深掘り skill (/wp-tamper など)
   ↓
実機反映 → postmortem → Claude 報告書ドラフト → 顧客・経営層送信
```

## 評価軸との対応

| 白浜評価軸 | このパイプラインの貢献 |
|---|---|
| 技術対応力 | analyzer + Mock + Claude で攻撃判定とコマンド生成 |
| 顧客対応 | Claude が顧客向け説明文を自動生成 |
| 報告・連絡 | `explain_to_operator_ja()` で経営層報告 |
| 報告書の質 | 04_完了報告テンプレ準拠の Claude ドラフト |
| プロセス遵守 | 検証層 + 人間承認ゲート |

## 使い方（最低限）

```bash
# 競技開始前（1 回）
bash scripts/feed/run_daily.sh             # 最新 CVE 取り込み
cp .env.example .env                       # ANTHROPIC_API_KEY 設定
python3 -c "from agent.backends.claude_backend import ClaudeBackend; ClaudeBackend()"  # 動通

# インシデント発生時
# 1. 電話受電 → 01_受電シート に時間窓と影響ホストを記入
# 2. Claude Code で /incident 13:00-13:30 victor を叩く
# 3. 提示された次の slash command（例: /wp-tamper）を叩く
# 4. リーダーが Go/NoGo 判断 → エンジニア B が実機反映
# 5. 報告書ドラフトを整形して顧客・経営層に送信
```

## 状態

- ✅ Phase A: コード持ち込み
- ✅ Phase B: ログ前処理スクリプト
- ⏳ Phase B': Loop1 (CVE feed) — fetch_cve.py のみ実装済、cve_to_pattern.py は TODO
- ⏳ Phase C: 白浜パターン拡張（analyzer.py に pattern_tag 追加） — TODO
- ✅ Phase D: slash command 雛形
- ⏳ Phase E: 既存ファイル微更新（01_、17_） — TODO
- ⏳ Phase F: 19_実装ガイド — TODO
- ⏳ §9 初日タスク（本番環境差分確認） — 競技初日に実施

## 参考

- セキュリティ・キャンプ 2026 ミニ B トラック教材（4層アーキ + 10ループ）
- `18_キャンプ知見の白浜活用方針.md` — 全体方針
- `~/.claude/plans/log-mock-mock-log-mock-mock-claude-api-delegated-lynx.md` — 実装プラン
