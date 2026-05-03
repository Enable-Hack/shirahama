# 20. VPN・SSH 接続手順（5/5 競技開始前 / 1 回だけ）

> 5/5 競技日の **朝 9:30 までに** 終わらせる接続セットアップ手順。
> 一度設定すれば 8 時間（= 1 日分）パスワード再入力不要。
> サーバ側は一切変更しない（authorized_keys 触らない）。

---

## 0. 認識合わせ — 認証情報は 3 種類ある

| 用途 | ユーザー名 | パスワード | 入力タイミング |
|---|---|---|---|
| **VPN 接続** | `booth11` 〜 `booth15`（5 人で割り当て） | `sccs2026-DmJYjc` | Mac の VPN 設定時 |
| **VPN 事前共有キー (PSK)** | (なし) | `sccs2026-DmJYjc` | 同上、別欄 |
| **サーバ ssh (一般)** | `manage` | `sh1Ra8mA` | `ssh bravo` 初回のみ |
| **サーバ ssh (root)** | `root` | `KCom10sT` | `ssh bravo-root` 初回のみ。bravo の sudo 不可問題で必要 |

クレデンシャル全量は [16_本番環境クイックリファレンス_whiskey.md §1](16_本番環境クイックリファレンス_whiskey.md#L21) を参照。

---

## 1. VPN 接続（Mac）

### 1.1 booth11-15 の割り当て確認

チームで決めた割当に従う。例:
- メンバー A → booth11
- メンバー B → booth12
- メンバー C → booth13
- メンバー D → booth14
- メンバー E → booth15

### 1.2 Mac の VPN 設定追加（システム設定 → ネットワーク → VPN）

```
種類      : L2TP (over IPsec)
表示名    : SCCS2026 whiskey
アドレス   : 133.42.49.151
アカウント名: booth1X  ← 自分の割当
認証設定:
  パスワード   : sccs2026-DmJYjc
  共有シークレット: sccs2026-DmJYjc
```

### 1.3 接続確認

```bash
# VPN ON 後
ifconfig ppp0 | grep inet
# → inet 10.1.X.Y (DHCP で割り当てられた IP) が表示されれば OK

ping -c 3 10.1.1.1   # bravo
ping -c 3 10.1.1.2   # victor
```

両方応答すれば次へ。応答無しなら VPN 設定見直し。

---

## 2. SSH ControlMaster 設定（**本命 / Option C**）

サーバには一切手を加えず、**Mac 側だけで** パスワード再入力をなくす方法。

### 2.1 ソケット置き場を作る（1 回だけ）

```bash
mkdir -p ~/.ssh/cm
chmod 700 ~/.ssh/cm
```

### 2.2 ~/.ssh/config に追記

```bash
# プロジェクトに用意したテンプレを ~/.ssh/config に追記
cat /Users/ryu/Desktop/shirahama/templates/ssh_config_sccs2026.conf >> ~/.ssh/config
chmod 600 ~/.ssh/config

# 確認
cat ~/.ssh/config | tail -60
```

### 2.3 各サーバに 1 回ずつ手動 ssh（パスワード入力 = ここだけ）

```bash
# bravo (manage) — パスワード sh1Ra8mA を入力
ssh bravo
# 入ったら exit で抜ける
exit

# bravo (root) — パスワード KCom10sT
ssh bravo-root
exit

# victor (manage) — sh1Ra8mA
ssh victor
exit

# victor (root) — KCom10sT
ssh victor-root
exit
```

→ 4 回のパスワード入力で **8 時間維持される接続が 4 本** 確立。

### 2.4 動作確認（パスワード不要を実証）

```bash
# 別ターミナルで実行 — パスワードプロンプトが出ずに即実行されれば成功
ssh victor 'echo OK $(hostname) $(date)'
ssh bravo  'echo OK $(hostname) $(date)'
ssh bravo-root 'whoami'
```

**`OK victor 2026-05-05 ...`** のように即返ってきたら設定完了。

### 2.5 これで Claude Code の Bash も通る

```bash
# /incident や spoke コマンドが内部でこう叩く:
ssh manage@10.1.1.2 'tail -2000 /var/log/httpd/access_log'

# ↑ ~/.ssh/config の Host 10.1.1.2 セクションが効いて
# ControlMaster 接続を再利用 → パスワード不要で実行
```

---

## 3. フォールバック手順（**Option D / ControlMaster が動かなかった場合**）

ControlMaster が何らかの理由で機能しない場合（古い OpenSSH / FreeBSD 側拒否設定 等）、**人間が並走で ssh 実行 → 結果ファイルを Claude に渡す** 方式に切替。

### 3.1 専用ターミナルを 2 つ開いておく

- ターミナル A: bravo 用 (`ssh bravo` 入った状態を維持)
- ターミナル B: victor 用 (`ssh victor` 入った状態を維持)

### 3.2 Claude が ssh コマンドを提示してきたら

Claude:
```
[Claude]: 「以下を別ターミナルで実行してください:」
          ssh manage@10.1.1.2 'tail -2000 /var/log/httpd/access_log' > /tmp/incident_access.log
```

人間:
1. ターミナル B（victor）で同じコマンドを **手で実行**
2. 結果を Mac の `/tmp/incident_access.log` に保存
   - サーバ → Mac のファイル転送が必要なら `scp manage@victor:/tmp/log /tmp/`
3. Claude に「実行完了、ファイルは /tmp/incident_access.log にあります」と伝える

### 3.3 Claude は `cat /tmp/incident_access.log` で読み込んで分析継続

→ 速度は落ちるが「絶対動く」保証あり。**Option C と D は併用可能**、C で進めて詰まったら D に逃げる。

---

## 4. 切れた接続の再確立

`ServerAliveInterval 60` で 60 秒に 1 回 keepalive 送るが、ネットワーク断で切れたら:

```bash
# 接続状態確認
ssh -O check victor
# → "Master running (pid=XXXX)" なら生きてる
# → "No master found" なら切れた

# 切れていたら再 ssh するだけで再確立
ssh victor 'echo reconnect ok'
# パスワード入力プロンプト → 入力 → 接続維持再開
```

---

## 5. 競技終了時のクリーンアップ

```bash
# 全 ControlMaster 接続を閉じる
ssh -O exit bravo
ssh -O exit bravo-root
ssh -O exit victor
ssh -O exit victor-root

# ソケットファイル確認 (空になっているはず)
ls ~/.ssh/cm/

# ~/.ssh/config から SCCS2026 セクションを削除（任意）
# 競技後は使わない設定なので、コメントアウト or 削除推奨
```

---

## 6. トラブルシュート

| 症状 | 原因 | 対処 |
|---|---|---|
| `ssh victor` でホスト解決できない | `~/.ssh/config` 追記忘れ | §2.2 やり直し |
| `Permission denied (publickey)` | サーバが公開鍵認証強制 | パスワード認証も試す: `ssh -o PreferredAuthentications=password victor` |
| `Connection refused` | VPN 切れた / サーバダウン | VPN 再接続 → ping 確認 |
| `Operation not permitted` (~/.ssh/cm/) | パーミッション | `chmod 700 ~/.ssh/cm` |
| ControlMaster がたまに効かない | ソケット arr が古い | `rm ~/.ssh/cm/*` してやり直し |
| Claude Code が ssh で止まる | パスワード認証になっている | Option D で並走、ControlMaster 接続が生きているか §4 で確認 |

---

## 7. パスワード保存場所まとめ

**自動化はしない**（sshpass / 鍵を ~/.ssh/config に書く等は **NG**）。
1 日 4 回手で打つだけなのでヒトの記憶 + 紙で十分。

| 媒体 | 内容 | 推奨 |
|---|---|---|
| 紙印刷 1 部（机上） | [16_本番環境クイックリファレンス §1](16_本番環境クイックリファレンス_whiskey.md#L21) を A4 印刷 | ✅ 必須（VPN 切れて Mac 落ちても紙は読める） |
| Mac の Keychain | 「セキュアノート」として 16_ §1 を保存 | ✅ Spotlight 検索可 |
| プロジェクト内 docs/16_ | 既存 | ✅ git 内・private repo なので OK |
| ~/.ssh/config | パスワード書き込み | ❌ 絶対 NG（プロセス一覧に漏れる） |
| sshpass / Keychain 連携 | 自動入力 | ❌ NG（履歴・プロセス一覧に痕跡） |
| 環境変数 | export PASSWORD=... | ❌ NG（子プロセスに継承される） |

---

## 8. ⚠️ 絶対やってはいけないこと（PDF + 18_ プレイブック §5 由来）

1. ❌ サーバ側 `~/.ssh/authorized_keys` への公開鍵追加（PDF「変更しない」違反、authorized_keys は configuration 改変）
2. ❌ サーバ側 sshd_config 編集
3. ❌ パスワード変更（`passwd` コマンド = settings.json deny に登録済）
4. ❌ ssh 接続ログを消す（PDF「ログは消さない・改ざんしない」）
5. ❌ 他チーム booth の VPN ID 使用 / 他チームのサーバへの ssh

---

## 9. 5/5 朝のチェックリスト（出発前 / 当日朝に確認）

```
[ ] VPN 設定が Mac に登録されている (booth1X / sccs2026-DmJYjc)
[ ] ~/.ssh/cm/ ディレクトリが存在する (mode 700)
[ ] ~/.ssh/config に SCCS2026 セクションが追記されている
[ ] templates/ssh_config_sccs2026.conf がプロジェクトにある
[ ] docs/16_本番環境クイックリファレンス §1 を A4 印刷した (紙)
[ ] チーム内で booth11-15 割り振りが確定している
[ ] §3 のフォールバック手順を全員が読んでいる
[ ] 競技開始 30 分前に VPN 接続テスト + §2.3 の 4 回 ssh を完了
```

---

## 改訂履歴

| 日付 | 内容 |
|---|---|
| 2026-05-01 | 初版作成（PDF 確認後の設定統合 / Option C 本命 + Option D フォールバック）|
