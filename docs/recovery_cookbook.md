# 復旧コマンドカタログ — 人間運用 reference

このカタログは AI が Read することを想定していない。受電 → /incident → /review の判定で attack_pattern が確定したあと、リーダーが該当章を開いて ssh で人手実行するための reference。

判定ロジック (どの章が該当するかの切り分け) は `/incident` §4 が attack_pattern として出力する。本書は「pattern が決まった後に何をやるか」だけを扱う。

---

## §1. DDoS (HTTP flood / DNS amp / SYN flood)

attack_pattern が DDoS 系で確定した後の緊急封じ込めコマンド。サービス影響あるのでリーダー承認 + 顧客通知後に実施する。

### HTTP flood — 同一 IP からの接続数制限

```bash
iptables -I INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j DROP
```

### SYN flood — レート制限と syncookies

```bash
iptables -A INPUT -p tcp --syn -m limit --limit 10/s -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
sysctl -w net.ipv4.tcp_syncookies=1
```

### DNS amplification — bravo (BIND) 緊急

```bash
# /etc/named.conf に rate-limit を追加 → rndc reload
```

### 攻撃元 IP の即時遮断 (汎用)

```bash
ssh manage@10.1.1.2 'sudo iptables -I INPUT -s <ATTACKER_IP> -j DROP'
```

注意: `iptables -j DROP` は settings.production.json で deny。AI は実行不可、人間が手で打つ。自機 IP への DROP (自爆) と全閉鎖 (`iptables -I INPUT -j DROP`) を生成しがちなので必ず cmd_validator を通すこと。

---

## §2. DNS 改ざん (BIND nsupdate / AXFR)

attack_pattern が DNS 改ざん系で確定した後、bravo (10.1.1.1 / FreeBSD) の named.conf を引き締めて reload する。`manage` は sudo 不可なので root 直ログイン (root パス `KCom10sT`)。

### named.conf に適用する差分

```text
options {
    ...
    allow-update { none; };
    allow-transfer { 10.1.130.1; };  # secondary のみ
    rate-limit {
        responses-per-second 10;
        window 5;
    };
};
```

### 適用手順 (人間がリーダー承認後に実施)

```bash
# 1. named.conf.new を作成 (上記差分を反映)
# 2. ssh root@10.1.1.1 で直ログイン (manage は sudo 不可)
ssh root@10.1.1.1
cp /usr/local/etc/namedb/named.conf /usr/local/etc/namedb/named.conf.bak
cp /usr/local/etc/namedb/named.conf.new /usr/local/etc/namedb/named.conf
named-checkconf /usr/local/etc/namedb/named.conf   # 構文 OK 確認
rndc reload
dig @10.1.1.1 com1.local SOA   # 疎通確認
```

注意: 競技中はこの差分を `cp` で当てるだけにする。本番中に named.conf を全書き換えはリスク高。

---

## §3. フィッシング / 不審メール対応

attack_pattern がフィッシング系で確定した後の遮断・キュー処置・全社通知。証拠保全のため `postsuper -d` 前に `postcat` で必ず保存する。

### postfix で特定送信元 IP をブロック

```bash
echo "1.2.3.4 REJECT" >> /etc/postfix/access
postmap /etc/postfix/access
postfix reload
```

### 不審メールのキュー削除 (証拠保全→削除)

```bash
postcat -q <queue_id> | tee /tmp/evidence_<queue_id>.eml
postsuper -d <queue_id>
```

### 全社向け注意喚起メール (Claude 生成文を流し込む)

```bash
# echo "<件名>" | mail -s "【重要】フィッシング注意" all_users@com1.local
```

注意: `postsuper -d` / `postmap` / `postfix reload` / Edit(/etc/**) は settings.production.json で deny。AI は実行不可、人間が手で打つ。

---

## §4. ランサムウェア / 横展開 / 内部不正

attack_pattern がランサム系で確定した後の緊急隔離。隔離は復旧不能リスクあり、必ずスナップショット取得 → リーダー承認 → 顧客承認の 3 段ゲート後に人間が手で実施する。

### ネットワーク遮断 (被害拡大防止)

```bash
iptables -I INPUT -j DROP
iptables -I OUTPUT -j DROP
```

注意: 全閉鎖は SSH も切れるので、コンソールアクセスを確保してから実施すること。

### 不審プロセス kill

```bash
# kill -9 <pid>
```

### 不審ユーザーログイン無効化

```bash
# usermod -L <username>
```

### pkexec SUID 削除 (PwnKit 緊急対応)

```bash
ssh manage@10.1.1.2 'sudo chmod -s /usr/bin/pkexec'
```

### obuchi/.ssh/authorized_keys 退避 (横展開ルート遮断)

```bash
mv /home/obuchi/.ssh/authorized_keys /tmp/evidence_obuchi_authkeys.bak
chmod 700 /home/obuchi
```

注意: `iptables` / `kill` / `userdel` / `usermod -L` / `chmod -s` 等は settings.production.json で deny。AI は実行不可、人間が手で打つ。`-j DROP` で `-s` なし / 自機 IP block / bravo に manage で sudo 等は cmd_validator が弾く。

---

## §5. WordPress / RainLoop / PHP 脆弱性

attack_pattern が WP/rainloop 改ざん系で確定した後の victor (10.1.1.2 / Rocky Linux) 上の遮断・退避。サービス影響あるのでリーダー承認 + 顧客通知後に実施。

### 攻撃元 IP の即時遮断 (HTTP / WP-login brute 緊急対応)

```bash
iptables -I INPUT -s <ATTACKER_IP> -j DROP
```

### WordPress xmlrpc.php / wp-cron.php の一時退避 (brute / amplification 遮断)

```bash
mv /var/www/wordpress/xmlrpc.php /var/www/wordpress/xmlrpc.php.disabled
mv /var/www/wordpress/wp-cron.php /var/www/wordpress/wp-cron.php.disabled
```

### wp-config.php の権限戻し (640 / owner=apache:apache)

```bash
chown apache:apache /var/www/wordpress/wp-config.php
chmod 640 /var/www/wordpress/wp-config.php
```

### uploads 配下の不審 PHP/PHTML/PHAR を退避 (webshell 即時隔離)

```bash
find /var/www/wordpress/wp-content/uploads -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.phar" \) -exec mv {} /tmp/evidence_webshell/ \;
```

### .htaccess に PHP 実行禁止を追加 (uploads 配下からの RCE 遮断)

```bash
cat >> /var/www/wordpress/wp-content/uploads/.htaccess <<'HTACCESS'
<FilesMatch "\.(php|phtml|phar|pl)$">
    Require all denied
</FilesMatch>
HTACCESS
```

### obuchi/.ssh/authorized_keys 退避 (横展開ルート遮断 / 18_ #8)

```bash
mv /home/obuchi/.ssh/authorized_keys /tmp/evidence_obuchi_authkeys.bak
chmod 700 /home/obuchi
```

### Apache 再読込 (上記 .htaccess / 退避を反映)

```bash
apachectl -t           # 構文チェック先
apachectl graceful
```

注意: 封じ込め系 + 復旧系 (`cp /etc/`, `mv /etc/`, `sysctl -w` 等) は settings.production.json で deny。AI は実行不可、人間が手で打つ。
