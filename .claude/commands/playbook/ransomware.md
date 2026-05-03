---
description: ランサムウェア / 横展開 / 内部不正対応。ファイル mtime と sudo ログから感染範囲特定
---

# /ransomware — ランサムウェア・横展開対応

## 0. 前提（必ず最初に確認）

- 対象: **両機**（victor 10.1.1.2 / bravo 10.1.1.1）— 横展開を疑うため両方を見る
- /incident の §0 共通定数を必ず参照
- ⚠️ 緊急隔離コマンド（`iptables -j DROP` / `usermod -L` / `chmod -s` / `kill -9`）は settings.json で **ask** 設定 = リーダー承認 + 顧客通知 + スナップショット取得**後**のみ
- ⚠️ 18_ §9「既侵害可能性」: 4/24 深夜に obuchi/manage が `10.1.129.10` からログイン痕跡 = **既に踏まれている前提で対応**
- ⚠️ 18_ §8「/home/obuchi 777」: 任意ユーザが authorized_keys 設置可 → 横展開の典型ルート

## 1. 追加収集コマンド（read-only）

### 1.1 ファイル変更痕跡（暗号化 / webshell / バックドア）

```bash
# 直近 1 時間で変更されたファイル (victor)
ssh manage@10.1.1.2 'sudo find / -xdev -type f -mmin -60 -not -path "/proc/*" -not -path "/sys/*" -not -path "/var/cache/*" 2>/dev/null | head -100'

# bravo は manage が sudo 不可なので root で
ssh root@10.1.1.1 'find / -type f -mtime -1 -not -path "/proc/*" 2>/dev/null | head -100'

# 不審な拡張子 (ランサム暗号化痕跡)
ssh manage@10.1.1.2 'sudo find / -type f \( -name "*.encrypted" -o -name "*.locked" -o -name "*.crypt" -o -name "*.enc" -o -name "*.cry" \) 2>/dev/null'

# ランサム置き手紙
ssh manage@10.1.1.2 'sudo find / -type f \( -name "README_*" -o -name "DECRYPT_*" -o -name "HOW_TO_*" -o -name "RECOVERY*" \) 2>/dev/null | head'

# webshell 痕跡 (uploads / tmp 配下の PHP)
ssh manage@10.1.1.2 'sudo find /var/www -path "*/uploads/*" -name "*.php" -o -path "*/tmp/*" -name "*.php" 2>/dev/null'
```

### 1.2 認証・権限痕跡（18_ #9, #51, #11 由来）

```bash
# 既侵害ベースライン: 不審 IP からの過去ログイン (10.1.129.x 等)
ssh manage@10.1.1.2 'last -F | head -20'
ssh root@10.1.1.1 'last -F | head -20'

# 現在のセッション (今この瞬間入っている人)
ssh manage@10.1.1.2 'who; w'
ssh root@10.1.1.1 'who; w'

# pkexec PwnKit 試行 (18_ #51 / analyzer SECURE_PATTERNS と一致)
ssh manage@10.1.1.2 'sudo grep -iE "pkexec.*GCONV_PATH|pkexec.*charset" /var/log/secure | tail -20'

# sudo 不正使用 (18_ analyzer privesc/sudo-unauthorized)
ssh manage@10.1.1.2 'sudo grep -iE "user NOT in sudoers|authentication failure|incorrect password" /var/log/secure | tail -30'

# UID 0 重複 (18_ #11 toor 問題 / bravo 特有)
ssh root@10.1.1.1 'awk -F: "$3==0 {print}" /etc/passwd'

# obuchi 777 ホームディレクトリ確認 (18_ #8)
ssh manage@10.1.1.2 'ls -ld /home/obuchi 2>/dev/null; sudo ls -la /home/obuchi/.ssh/ 2>/dev/null'

# 不審なユーザー追加痕跡
ssh manage@10.1.1.2 'sudo tail -30 /var/log/secure | grep -iE "useradd|usermod|adduser"'
```

### 1.3 永続化（cron / at / systemd / SUID 増殖）

```bash
# crontab (root + 全ユーザー)
ssh manage@10.1.1.2 'sudo cat /etc/crontab; sudo ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/'
ssh manage@10.1.1.2 'for u in $(cut -d: -f1 /etc/passwd); do sudo crontab -u $u -l 2>/dev/null && echo "^^ $u ^^"; done'

# at job (18_ #52 / analyzer persist/at-job)
ssh manage@10.1.1.2 'sudo atq; sudo ls -la /var/spool/at/ 2>/dev/null'

# systemd timer
ssh manage@10.1.1.2 'systemctl list-timers --all 2>&1 | head -30'

# 新規 SUID (pkexec 以外で増えていないか / 18_ #51 #52 由来)
ssh manage@10.1.1.2 'sudo find / -xdev -perm -4000 -type f -mtime -7 2>/dev/null'
```

### 1.4 プロセス・接続状態

```bash
# 親子関係 + 不審プロセス
ssh manage@10.1.1.2 'ps auxf 2>&1 | head -80'

# 外向け接続 (C2 通信痕跡)
ssh manage@10.1.1.2 'sudo ss -tnp 2>&1 | grep -v 127.0.0.1 | head -40'
ssh root@10.1.1.1 'sockstat -4c 2>&1 | head -40'

# 開いているポート (新規 backdoor リスナー検出)
ssh manage@10.1.1.2 'sudo ss -tlnp 2>&1'
```

### 1.5 解析ツール投入

```bash
# secure / auth.log を analyzer の SECURE_PATTERNS に流す
ssh manage@10.1.1.2 'sudo tail -1000 /var/log/secure' > /tmp/incident_secure.log
ssh root@10.1.1.1 'tail -1000 /var/log/auth.log' > /tmp/incident_auth.log
# analyzer.run() → privesc/pkexec-attempt, privesc/sudo-unauthorized, auth/ssh-bruteforce が出る
```

## 2. Mock パターン参照

`analyzer.py` の以下:
- `pkexec-attempt`（PwnKit CVE-2021-4034）
- `sudo/unauthorized`
- 不審ファイル mtime（要実装）

## 3. Claude 投入用プロンプト

```
以下は victor で観測された不審な活動です。
ランサムウェア感染 / 横展開 / 内部不正のいずれか判定してください。

直近変更ファイル: <貼る>
sudo / pkexec ログ: <貼る>
プロセス一覧: <貼る>

出力:
1. 攻撃種別判定（ランサム / クリプトジャック / バックドア / 内部不正）
2. 感染範囲推定（影響を受けたディレクトリ・ユーザー）
3. 緊急隔離コマンド（ネットワーク遮断 / プロセス kill / 該当ユーザー無効化）
4. 顧客向け第一報（業務停止判断含む）
5. 経営層向け緊急報告（300 字、判断を仰ぐ事項を明記）
```

## 4. 既存 playbook 参照

- `03_シナリオ別対応プレイブック.md` §3「ランサムウェア」
- `インシデント対応_基本マニュアル.md` 医療シナリオ（業務継続 vs 隔離の判断）

## 5. 報告書テンプレ生成指示

`04_完了報告テンプレート.md` の構造で出力。
**ランサム時は時系列ログが極めて重要** — 何時何分に何が起きたかを分単位で記録。

## 6. 復旧/封じ込めコマンド (人間が手で実行)

⚠️ 以下は **すべて人間がリーダー承認後に手で実行する**コマンドです。
AI は表示・検証・突合のみ。実行には関与しません。
理由:
- タイポ / 不完全な diff / 旧設定上書きで復旧失敗 → サービスダウン継続のリスク
- settings.production.json で物理的に deny されているため AI 実行は不可
- チームが「自分たちで何を直しているか」を理解する必要がある（競技後の説明責任）
- ランサム特有: 隔離は復旧不能リスクあり、必ずスナップショット + 顧客承認後のみ実施

```text
# ネットワーク遮断（被害拡大防止 / 全閉鎖は SSH も切れるので注意）
iptables -I INPUT -j DROP
iptables -I OUTPUT -j DROP

# 不審プロセス kill
# kill -9 <pid>

# 不審ユーザーログイン無効化
# usermod -L <username>

# pkexec SUID 削除（PwnKit 緊急対応）
# chmod -s /usr/bin/pkexec

# obuchi/.ssh/authorized_keys 退避 (横展開ルート遮断)
# mv /home/obuchi/.ssh/authorized_keys /tmp/evidence_obuchi_authkeys.bak
# chmod 700 /home/obuchi
```

→ 表示後、§7 cmd_validator gate を必ず通すこと (自爆 -j DROP / 触禁ホスト弾き)。
→ スナップショット取得 → リーダー承認 → 顧客承認の 3 段ゲート後に人間が手で実施。

## 7. コマンド検証ゲート（封じ込めコマンド提示時 必須）

§6 のような `iptables -j DROP` / `kill -9` / `usermod -L` / `chmod -s` 等を 1 行でも提示する場合、**リーダーに見せる前に必ず `agent/cmd_validator.py` を通すこと**。settings.production.json で iptables / kill / userdel / usermod -L / chmod -s 等は deny になっており **AI は実行できない** — 提案文字列の事故防止が validator の役割。

特にこの playbook は `iptables -I INPUT -j DROP` (全閉鎖事故) や 自機 IP への DROP (自爆) を生成しがちなので **必ず通す**。

```bash
cat > /tmp/playbook_proposed.sh <<'EOF'
# ※リーダー承認後 + 顧客通知後に人間が手で実行すること
ssh manage@10.1.1.2 'sudo chmod -s /usr/bin/pkexec'
ssh manage@10.1.1.2 'sudo usermod -L <username>'
EOF

PYTHONPATH=. ${SHIRAHAMA_PY:-python3} -m agent.cmd_validator /tmp/playbook_proposed.sh
echo "exit=$?"
```

判定:
- `exit=0` ✅ — リーダーに提示してよい。承認後に**人間が手で打つ**
- `exit=1` 🚨 — ERROR あり。`-j DROP` で `-s` なし / 自機 IP block / bravo manage で sudo 等を弾く
- WARN のみ — 提示してよいが補足説明を添える

## 8. JSON 永続化（HTML dashboard 連携）

§6 の対策コマンド + §7 の cmd_validator 結果を JSON 化して helper に渡す。actor は `ai_human` (AI 提案 → 人間実行) を明示。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh playbook-ransomware --actor ai_human
{
  "inputs": {
    "scenario": "ransomware",
    "incident_id": "$INCIDENT_ID"
  },
  "outputs": {
    "proposed_commands": [
      "<§6 で提案したコマンド全文 (1 行 1 件)>"
    ],
    "cmd_validator_result": {
      "exit_code": 0,
      "errors": [],
      "warnings": ["<§7 cmd_validator が出した WARN/ERROR>"]
    },
    "scope": {
      "in_scope": ["<受電内容と直結する対策>"],
      "out_of_scope_logged": ["<観察したが今回触らないもの (治しすぎない哲学)>"]
    }
  },
  "verdict": {
    "status": "🚨 | ⚠️ | ✅",
    "summary": "<提案 N 件 (validator PASS), 採用は人間判断>"
  },
  "next_skills": ["/report", "/ticket"]
}
JSON_EOF
```

- `actor=ai_human` で「AI が提案、人間が実行」を JSON 上で明示 (dashboard が UI 上で「未実行/実行済」バッジを出せる)
- `proposed_commands[]` は §6 で提案した対策コマンドを 1 行 1 件で羅列。`text` フェンス内のコマンドをそのまま転記
- `cmd_validator_result` は §7 で実行した `agent.cmd_validator` の exit_code + errors + warnings をそのまま入れる
- `scope.out_of_scope_logged` で「観察したが今回触らない」項目を残し、報告書/ticket での記録に使う (治しすぎない哲学)
- 保存先: `data/incidents/${INCIDENT_ID}/playbook-ransomware__<ts>.json`
