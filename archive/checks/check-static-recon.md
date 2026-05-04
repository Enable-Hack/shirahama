---
model: claude-haiku-4-5
description: 静的設定の一括 recon (旧 7 check 統合) — MariaDB EOL / BIND バージョン / sendmail.cf 流用 / nkf RPM 残骸 / VM 環境 / SELinux+iptables baseline / Squid 未起動状態 を read-only で確認
---

# /check:check-static-recon — 静的設定 recon (一括版)

引数: `<時間窓> <ホスト>` (時間窓は使わないが互換のため受ける)
例: `/check:check-static-recon - victor`

## 0. 前提

- **静的検査の集約版**。以下 7 check を 1 ファイルに統合した:
  - `mariadb-eol`        — MariaDB 10.3 (EOL 2023-05) 該当バージョン確認
  - `bind-version`       — BIND 9.11.36 等の既知 CVE 該当確認
  - `sendmail-old-cf`    — sendmail.cf 旧サイト流用 / ACL 不整合
  - `nkf-rpm-residue`    — `/root/*.rpm` 等の手動 localinstall 残骸
  - `vm-detection`       — Hypervisor 検出 (Proxmox 等の MAC OUI / dmidecode)
  - `baseline-hardening` — SELinux / pf / firewalld / iptables 状態
  - `squid-installed-not-running` — Squid 未起動状態 (即起動可能リスク)
- 攻撃検知ではなく **報告書記載 + 「他 check の前提」確認** が主目的
- 受電直後の状況把握用に 1 回だけ叩く想定。動的に切替えるシーンはない
- read-only。設定変更 / サービス起動は一切しない
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
SSH_VICTOR="${SSH_VICTOR:-manage@10.1.1.2}"
SSH_BRAVO="${SSH_BRAVO:-manage@10.1.1.1}"
```

## 1. 収集 (read-only)

両機並行で実行する。OS 差は `uname -s` で吸収。

```bash
echo "═══ /check:check-static-recon ═══"

run_static_recon() {
    local label="$1"
    local host="$2"
    local os
    os=$(ssh -o ConnectTimeout=5 -o BatchMode=yes "$host" 'uname -s' 2>/dev/null || echo UNKNOWN)
    echo "─── $label ($os) ───"

    # ─── A. MariaDB EOL ─────────────────────────────────
    echo "[A] MariaDB version:"
    ssh -o BatchMode=yes "$host" 'rpm -q mariadb-server 2>/dev/null;
        mysql --version 2>/dev/null;
        mysqld --version 2>/dev/null' | grep -v "^$" | sed 's/^/    /'

    # ─── B. BIND version ────────────────────────────────
    if [ "$label" = "bravo" ]; then
        echo "[B] BIND version:"
        ssh -o BatchMode=yes "$host" 'named -v 2>/dev/null;
            pkg info bind\* 2>/dev/null | head -5;
            rndc status 2>/dev/null | head -5' | grep -v "^$" | sed 's/^/    /'
        # 外部からの version.bind chaos クエリ (攻撃者にも見えてる物証)
        echo "[B-ext] version.bind chaos:"
        dig version.bind chaos txt @"$host" +short +time=2 +tries=1 2>/dev/null | sed 's/^/    /'
    fi

    # ─── C. sendmail.cf 流用 ───────────────────────────
    echo "[C] sendmail.cf build info:"
    ssh -o BatchMode=yes "$host" \
        'sudo grep -iE "built by|##### built|DZ" /etc/mail/sendmail.cf 2>/dev/null | head -3;
         sudo cat /etc/mail/local-host-names 2>/dev/null | head -5;
         sudo cat /etc/mail/relay-domains 2>/dev/null | head -5' | sed 's/^/    /'

    # ─── D. /root の RPM 残骸 + dnf history ─────────────
    if [ "$os" = "Linux" ]; then
        echo "[D] localinstall residue:"
        ssh -o BatchMode=yes "$host" 'sudo ls -la /root/*.rpm /root/*.tar.gz 2>/dev/null;
            sudo dnf history list 2>/dev/null | head -5' | sed 's/^/    /'
    fi

    # ─── E. VM detection ────────────────────────────────
    echo "[E] VM detection:"
    if [ "$os" = "Linux" ]; then
        ssh -o BatchMode=yes "$host" 'sudo dmidecode -s system-manufacturer 2>/dev/null;
            sudo dmidecode -s system-product-name 2>/dev/null;
            grep -i hypervisor /proc/cpuinfo 2>/dev/null | head -1;
            ip link show 2>/dev/null | grep -iE "ether" | head -3' | sed 's/^/    /'
    elif [ "$os" = "FreeBSD" ]; then
        ssh -o BatchMode=yes "$host" 'sysctl kern.vm_guest 2>/dev/null;
            ifconfig 2>/dev/null | grep -iE "ether" | head -3' | sed 's/^/    /'
    fi

    # ─── F. baseline hardening (SELinux / firewall) ─────
    echo "[F] baseline hardening:"
    if [ "$os" = "Linux" ]; then
        ssh -o BatchMode=yes "$host" 'getenforce 2>/dev/null;
            sudo grep -iE "^SELINUX=" /etc/selinux/config 2>/dev/null;
            sudo systemctl is-active firewalld 2>/dev/null;
            sudo iptables -L INPUT -n 2>/dev/null | head -5' | sed 's/^/    /'
    elif [ "$os" = "FreeBSD" ]; then
        ssh -o BatchMode=yes "$host" 'sudo grep -iE "^(pf|ipfw)_enable" /etc/rc.conf 2>/dev/null;
            sudo pfctl -s info 2>/dev/null | head -5;
            sudo ipfw -a list 2>/dev/null | head -5' | sed 's/^/    /'
    fi

    # ─── G. Squid 未起動 (即起動可能リスク) ─────────────
    if [ "$os" = "Linux" ]; then
        echo "[G] Squid status:"
        ssh -o BatchMode=yes "$host" 'rpm -q squid 2>/dev/null;
            sudo systemctl is-active squid 2>/dev/null;
            sudo systemctl is-enabled squid 2>/dev/null;
            sudo ss -tlnp | grep -E ":(3128|8080)\b" 2>/dev/null' | sed 's/^/    /'
    fi
    echo
}

run_static_recon victor "$SSH_VICTOR" &
run_static_recon bravo  "$SSH_BRAVO"  &
wait
```

## 2. 検知パターン (Claude が出力を読んで判定)

| 観点 | 危険シグナル | 重要度 |
|---|---|---|
| MariaDB | 10.3.x / 10.5 未満 = EOL | ⚠️ 報告書記載 |
| BIND | 9.11.36 / 9.16 系で未パッチ | ⚠️ 報告書記載 |
| sendmail.cf | 旧サイト hostname 残存 / Cw 不整合 | ⚠️ ACL 確認 |
| /root の RPM | nkf や類似の手動 install 痕跡 | ⚠️ 棚卸し記録 |
| VM | Proxmox / VMware 検出 | ✅ 単に記録 (escape は別検知) |
| SELinux | Disabled / Permissive | 🚨 他 check の信頼性下げる前提 |
| iptables | 全 ACCEPT / pf inactive | 🚨 「単一脆弱で全機制圧」前提 |
| Squid | installed + not active | ⚠️ 「即起動可能」を §6 サマリに記載 |

## 3. 判定基準

- ✅ **正常**: 上記すべて hardened (SELinux Enforcing / firewall active / 旧 cf なし)
- ⚠️ **記録のみ**: EOL バージョン / 設定残骸 — 報告書に注記、他 check の前提として参照
- 🚨 **即対応推奨**: SELinux Disabled + iptables 全 ACCEPT — 他 check で攻撃確定なら lateral movement 容易、リーダー承認後に最低限の hardening を提案

## 4. 次のアクション

- 結果を /report の「環境前提」セクション + /ticket の「原因」根本要因として転記
- 連鎖：
  - MariaDB EOL → `/check:check-mysql-x-direct` (DB 直接攻撃の物証確認)
  - sendmail.cf 流用 → `/check:check-sendmail-open-relay`
  - SELinux/iptables disabled → `/playbook:ransomware` の lateral movement 評価で重み付け

## 5. JSON 永続化

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-static-recon
{
  "inputs": {"target_host": "both"},
  "outputs": {
    "mariadb_version":   "...",
    "bind_version":      "...",
    "sendmail_cf_build": "...",
    "rpm_residues":      ["...必要なら..."],
    "vm_environment":    "...",
    "selinux":           "Enforcing|Permissive|Disabled",
    "firewall":          "active|inactive",
    "squid_state":       "not-installed|installed-inactive|active",
    "raw_output":        "(任意の生 output 抜粋)"
  },
  "verdict": {
    "status": "🚨|⚠️|✅",
    "summary": "(各観点の 1 行サマリ)"
  },
  "next_skills": ["/check:check-...", "/playbook:..."]
}
JSON_EOF
```

保存先: `data/incidents/${INCIDENT_ID}/check-static-recon__<ts>.json`
