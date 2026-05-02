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

## 6. 緊急隔離コマンド雛形（破壊的なので絶対に承認後）

```bash
# ⚠️ 全部リーダー + 顧客承認後のみ

# ネットワーク遮断（被害拡大防止）
iptables -I INPUT -j DROP
iptables -I OUTPUT -j DROP

# 不審プロセス kill
# kill -9 <pid>

# 不審ユーザーログイン無効化
# usermod -L <username>

# pkexec SUID 削除（PwnKit 緊急対応）
# chmod -s /usr/bin/pkexec
```

⚠️ **隔離は復旧不能なリスクあり、必ずスナップショット取得後に実施**
