#!/usr/bin/env python3
"""
docs/shirahama_test_log{,2,3}.md からターミナルセッション中の `cat` / `tail` / `head`
ブロックを抽出して、対象ファイル別に保存する。

セッションは以下の形をしている:

    [manage@bravo ~]$ cat /etc/resolv.conf
    nameserver 10.1.130.1
    nameserver 10.1.6.1
    [manage@bravo ~]$ <次のコマンド>

→ プロンプト行の次の行から、次のプロンプト行の手前までを「resolv.conf の中身」として切り出す。

【テスト環境ログの実態】
docs/shirahama_test_log{,2,3}.md は **偵察セッション**（攻撃なし）であり、
含まれるのは主に以下:

  - /etc/* の設定ファイル（resolv.conf / hosts / named.conf / httpd.conf / mysql my.cnf 等）
  - /var/www/* のバージョンファイル（WP / rainloop の version.php）
  - /var/log/ は ls 結果のみ（中身は ほぼ無い）
  - service / ps / netstat / sockstat 等のシステム状態

→ つまり用途は **「想定環境と実環境の一致検証」** がメイン:
   - 14_サーバ調査レポート の前提（PHP 7.2.24, WP 4.9.4, BIND allow-update 等）が
     現環境と乖離していないか cross-check
   - .claude/commands で参照しているパスや設定が実在するか確認

使い方:
    python tests/extract_test_logs.py docs/shirahama_test_log.md  tests/fixtures/test_env_baseline/
    python tests/extract_test_logs.py docs/shirahama_test_log2.md tests/fixtures/test_env_baseline/ --append
    python tests/extract_test_logs.py docs/shirahama_test_log3.md tests/fixtures/test_env_baseline/ --append

抽出ルール:
- プロンプト行を識別: [user@host ~]$ / [user@host ~]# / user@Mac ~ %
- 対象コマンド: cat / sudo cat / tail / head / less / more（オプション付き可）
- 抽出パスのドメイン: /etc/, /var/, /usr/local/etc/
- 出力ファイル名: <host>__<full_path_with_underscores>
  例: bravo__etc_resolv.conf, victor__etc_httpd_conf_httpd.conf
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

# プロンプトパターン
PROMPT_PATTERNS = [
    re.compile(r"^\[(?P<user>\w+)@(?P<host>\w+)[^\]]*\]\$\s*(?P<cmd>.*)$"),
    re.compile(r"^\[(?P<user>\w+)@(?P<host>\w+)[^\]]*\]#\s*(?P<cmd>.*)$"),
    re.compile(r"^(?P<user>\w+)@(?P<host>[\w.-]+)\s+[^%]*%\s*(?P<cmd>.*)$"),
    re.compile(r"^(?P<user>\w+)@(?P<host>[\w.-]+):[^$]*\$\s*(?P<cmd>.*)$"),
]

# 対象コマンド: cat / tail / head / less / more (sudo 可、オプション可)
# 抽出するパスは /etc/, /var/, /usr/local/etc/ 配下
FILE_CMD_RE = re.compile(
    r"^\s*(?:sudo\s+)?(?:cat|tail|head|less|more)"
    r"(?:\s+-\w+)*"
    r"\s+(?P<path>(?:/etc/|/var/|/usr/local/etc/|/usr/local/www/)[\w./*-]+)"
)


def parse_prompt(line: str) -> tuple[str, str, str] | None:
    """プロンプト行を user/host/cmd に分解。プロンプトでなければ None."""
    for pat in PROMPT_PATTERNS:
        m = pat.match(line)
        if m:
            return m.group("user"), m.group("host"), m.group("cmd")
    return None


def extract_target_path(cmd: str) -> str | None:
    """コマンド文字列から対象パスを取り出す。それ以外は None."""
    m = FILE_CMD_RE.match(cmd)
    if m:
        return m.group("path")
    return None


def output_filename(host: str, target_path: str) -> str:
    """出力ファイル名: <host>__<path_with_underscores>
    例: bravo__etc_resolv.conf, victor__var_www_rain_rainloop_data_VERSION
    """
    sanitized = target_path.lstrip("/").replace("/", "_").replace("*", "wildcard")
    return f"{host}__{sanitized}"


def extract(input_md: Path) -> dict[str, list[str]]:
    """1 つの md ファイルから、ホスト×ファイル別に行を抜き出す。
    返り値: {output_filename: [lines]}
    """
    lines = input_md.read_text(encoding="utf-8").splitlines()
    extracted: dict[str, list[str]] = {}

    current_output: str | None = None
    current_host: str | None = None
    in_capture_block = False

    for line in lines:
        prompt = parse_prompt(line)
        if prompt is not None:
            user, host, cmd = prompt
            current_host = host
            target_path = extract_target_path(cmd)
            if target_path:
                # 新しい抽出ブロック開始
                output_name = output_filename(host, target_path)
                current_output = output_name
                extracted.setdefault(output_name, [])
                in_capture_block = True
            else:
                in_capture_block = False
                current_output = None
            continue

        # プロンプトでない行 = 直前コマンドの出力
        if in_capture_block and current_output:
            extracted[current_output].append(line)

    return extracted


def main() -> int:
    parser = argparse.ArgumentParser(
        description="docs/shirahama_test_log*.md から偵察キャプチャを抽出"
    )
    parser.add_argument("input", type=Path, help="入力 md ファイル")
    parser.add_argument("out_dir", type=Path, help="出力ディレクトリ")
    parser.add_argument(
        "--append",
        action="store_true",
        help="既存ファイルに追記（複数 md を順に処理する場合）",
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"ERR: input not found: {args.input}")
        return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)

    blocks = extract(args.input)
    mode = "a" if args.append else "w"

    if not blocks:
        print(f"WARN: 抽出ブロックが見つかりませんでした: {args.input}")
        return 0

    for fname, content in blocks.items():
        out_path = args.out_dir / fname
        with out_path.open(mode, encoding="utf-8") as f:
            if args.append and out_path.exists() and out_path.stat().st_size > 0:
                f.write(f"\n# === appended from {args.input.name} ===\n")
            f.write("\n".join(content))
            if content and not content[-1].endswith("\n"):
                f.write("\n")
        print(f"  -> {out_path} ({len(content)} lines)")

    print(f"OK: {len(blocks)} block(s) extracted from {args.input}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
