# 次にやること — incident: 2026-05-04_05:00_bravo_victor

## いまの進捗

| ステージ | 状態 | 備考 |
|---|---|---|
| preflight | [DONE] | 両機 healthy、victor named は inactive (想定通り) |
| incident | [DONE] | phishing カテゴリ確定、verdict=CRITICAL |
| check | [PARTIAL] | obuchi-777-hijack 1 本のみ。STEP 1 必須 2 本未実行 |
| review | [TODO] | 4 択判定の採択 JSON 未保存 |
| playbook | [DONE] | 提案 + 効果確認 6/6 PASS |
| report | [DONE] | full_done モード (完全完了) |
| ticket | [TODO] | PukiWiki マークアップ未生成 |

---

## 残タスク 4 つ (優先順)

### 1. `/ticket` 生成 (最優先)

- 大会本番の評価軸「チケット記載の正確さ・網羅性」に直結
- PukiWiki 構文で出力: 発生時刻 / トラブル内容 / 原因 / 対処内容 / 復旧確認
- 原因セクションには**実ログ行を引用**するのが必須
- いま何もない状態
- コマンド: `/ticket`

### 2. review タブで 4 択採択 (中)

- ブラウザで review タブを開く
- 操作:
  1. 4 択ラジオで `D. 対応必要` を選ぶ
  2. 派生フィールド (事象分類 = phishing、/playbook = /playbook:phishing) を埋める
  3. ヘッダの「採択 JSON 保存」ボタンクリック
  4. ダウンロードされた `review_human__*.json` を `data/incidents/2026-05-04_05:00_bravo_victor/` に移動
- 結果: フロー widget の review ステージが [DONE] になる

### 3. STEP 1 必須 check 補完 (任意)

incident.md §5.1 では「常に最初に並行起動」と定義されてる 2 本がまだ未実行:

- `/check:check-known-attacker-ip` — 10.1.129.10 由来の活動 (既侵害前提の根拠)
- `/check:check-syslog-udp-injection` — ログ自体の汚染確認

実害は既に把握済 (obuchi バックドア確定) だが、設計上の網羅性として叩く。

### 4. 24 時間監視 (任意)

- 明日同時刻に v4 再実行: `ssh victor 'sudo grep "161.33.12.212" /var/log/maillog | tail -3'`
- 新規攻撃 0 件なら「再発なし」確証

---

## ゴール別おすすめ

| やりたいこと | 順番 |
|---|---|
| 大会本番フロー完走を体験 | `/ticket` だけ |
| dashboard の全カード埋める | review 採択 → `/ticket` |
| 設計通りの完全な調査 | STEP 1 check 2 本 → review → `/ticket` |
| ここで終わり | git commit で保管 |

---

## いまの主な事実 (報告書用にまとめ)

- 攻撃元: 161.33.12.212 (Akamai 攻撃 VM)
- 攻撃手法: IMAP/SMTP brute-force + obuchi アカウント SSH バックドア仕込み
- 試行ユーザ: rocky / guest / test / wpadmin / webmaster / admin / root / operator / manager / obuchi (10 名)
- 攻撃時間: 2026-05-04 05:02:16 - 05:02:22 UTC (HTTP flood ピーク 6 秒)
- バックドア: /home/obuchi/.ssh/authorized_keys に attacker@10.1.129.10 鍵が May 3 08:53 UTC に追加
- 封じ込め実施時刻: 2026-05-04 07:50 UTC 頃
- 効果確認: 6/6 PASS (詳細は verification_run__*.json)
- 情報漏洩: 確認なし (全認証試行は失敗)
- 残作業: obuchi 氏のパスワード再発行は運用側で実施

## ファイル構成 (data/incidents/2026-05-04_05:00_bravo_victor/)

```
preflight__20260504T071549Z.json         (2628 bytes)
incident__20260504T072158Z.json          (2643 bytes)
checks__20260504T073936Z.json            (2514 bytes)
check-obuchi-777-hijack__20260504T075003Z.json  (1471 bytes)
playbook-phishing__20260504T075003Z.json (6631 bytes)  ← verification_commands + success_criteria 追加済
report__20260504T075754Z.json            (2708 bytes)  ← 旧: first_response_only
verification_run__20260504T082415Z.json  (2517 bytes)  ← 効果確認 6/6 PASS の生結果
report__20260504T082415Z.json            (3486 bytes)  ← 新: full_done モード
next_steps.md                            (このファイル)
```
