---
description: ランサムウェア / 横展開 / 内部不正対応。ファイル mtime と sudo ログから感染範囲特定
---

# /ransomware — ランサムウェア・横展開対応

## 1. 追加収集コマンド

```bash
# 直近 1 時間で変更されたファイル（暗号化痕跡）
ssh manage@10.1.1.2 'find / -type f -mmin -60 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -100'

# 不審な拡張子（.encrypted, .locked, .crypt 等）
ssh manage@10.1.1.2 'find / -type f \( -name "*.encrypted" -o -name "*.locked" -o -name "*.crypt" \) 2>/dev/null'

# ランサム置き手紙（README_*.txt, DECRYPT_*.html 等）
ssh manage@10.1.1.2 'find / -type f \( -name "README_*" -o -name "DECRYPT_*" -o -name "HOW_TO_*" \) 2>/dev/null | head'

# pkexec / sudo 不正使用
ssh manage@10.1.1.2 'grep -i "pkexec\|GCONV_PATH" /var/log/secure | tail -20'

# プロセス親子関係
ssh manage@10.1.1.2 'ps auxf | head -50'

# 不審な永続化（cron / systemd timer）
ssh manage@10.1.1.2 'crontab -l 2>&1; echo ---; systemctl list-timers 2>&1 | head'
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
