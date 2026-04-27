"""
ai-agent.renderers.nginx_renderer

PatchProposal を nginx の if 文構文に変換する。

制約:
    - body マッチは nginx 単体では困難（ngx_http_lua_module 等が必要）→ skip
    - header マッチは header 名の特定が必要だが、本レンダラでは未対応 → skip
    - target スコーピングは出力コメントで伝えるのみ
      （実際の location ブロックへの配置は patcher.py の責務）

想定される配置:
    出力された if 文は、対象 target に対応する nginx の location または
    server ブロック内に配置する前提。waf rules 用の共通 include ファイル
    として保存する想定。

教材上の位置づけ:
    - LLM 出力をそのまま nginx conf に書かない
    - 中立表現 → 専用レンダラ → 具体構文 の分離パターン
    - skip_reason を明示することで「何が renderable で何が不可能か」を
      受講者が言語化できる教材にする
"""
from __future__ import annotations

from dataclasses import dataclass
import re as _re
from typing import Literal

from ..llm import PatchProposal

# RenderResult.status のラベル
RenderStatus = Literal["rendered", "skipped"]


@dataclass
class RenderResult:
    """
    1件の PatchProposal に対するレンダリング結果。

    status == "rendered" のとき nginx_snippet が非 None。
    status == "skipped" のとき skip_reason が非 None。
    """
    rule_id: str
    patch: PatchProposal
    status: RenderStatus
    nginx_snippet: str | None = None
    skip_reason: str | None = None


# ─── 公開関数 ─────────────────────────────────────────
def render_patch(patch: PatchProposal) -> RenderResult:
    """1件の PatchProposal を nginx 構文にレンダリングする。"""
    # match_type=body は nginx 単体では困難
    if patch.match_type == "body":
        return RenderResult(
            rule_id=patch.rule_id,
            patch=patch,
            status="skipped",
            skip_reason=(
                "nginx 単体では body マッチは困難です。"
                "ngx_http_lua_module または ModSecurity 等の "
                "WAF 専用モジュールの導入を検討してください。"
            ),
        )

    # match_type=header は特定のヘッダ名への対応が必要
    if patch.match_type == "header":
        return RenderResult(
            rule_id=patch.rule_id,
            patch=patch,
            status="skipped",
            skip_reason=(
                "header マッチは対象ヘッダ名の特定が必要です。"
                "本レンダラでは未対応のためスキップします。"
            ),
        )

    # 条件式を構築
    condition = _build_condition(patch)
    if condition is None:
        return RenderResult(
            rule_id=patch.rule_id,
            patch=patch,
            status="skipped",
            skip_reason=(
                f"未対応の match_type/operator 組合せ: "
                f"{patch.match_type}/{patch.match_operator}"
            ),
        )

    # アクション本体を構築
    action_body = _build_action_body(patch)

    # snippet 全体を組み立て
    snippet = _assemble_snippet(patch, condition, action_body)

    return RenderResult(
        rule_id=patch.rule_id,
        patch=patch,
        status="rendered",
        nginx_snippet=snippet,
    )


def render_patches(patches: list[PatchProposal]) -> list[RenderResult]:
    """複数の PatchProposal をまとめてレンダリングする。"""
    return [render_patch(p) for p in patches]


# ─── 内部: 条件式の構築 ─────────────────────────────────
def _build_condition(patch: PatchProposal) -> str | None:
    """
    match_type + match_operator + match_value から nginx if 条件文字列を作る。
    未対応の組合せの場合は None を返す。

    operator 別の扱い:
        - equals: 文字列完全一致（nginx の = 演算子）
        - prefix: 前方一致。match_value は文字列リテラルとして扱うため、
                  re.escape() で regex メタ文字 (. ( ) ? + * [ ] \\ 等) を
                  エスケープした上で ^ アンカー付き regex として評価する
        - contains: 部分一致。同じく re.escape() で文字列リテラル化する
        - regex: 生の正規表現としてそのまま評価（(?i) などのフラグは
                 呼出側が patch.match_value に直接埋める）

    重要: prefix / contains で re.escape() をしないと、match_value に含まれる
    '.' '(' '?' などが regex メタ文字として解釈され、意図しない誤検知の
    原因になる（例: contains "sleep(5)" が "sleep5" にもマッチするなど）。
    """
    nginx_var = _nginx_variable_for_match_type(patch.match_type)
    if nginx_var is None:
        return None

    if patch.match_operator == "equals":
        # 文字列完全一致。regex ではないので re.escape は不要、
        # nginx 文字列エスケープ（" のみ）だけ施す。
        escaped = _escape_nginx_string(patch.match_value)
        return f'{nginx_var} = "{escaped}"'

    if patch.match_operator == "prefix":
        # 前方一致。match_value を文字列リテラルとして扱い、
        # regex メタ文字をエスケープ → ^ アンカーを付けて regex として評価。
        literal = _re.escape(patch.match_value)
        # さらに nginx 文字列として安全にするため " のみエスケープ
        escaped = _escape_nginx_string(literal)
        return f'{nginx_var} ~ "^{escaped}"'

    if patch.match_operator == "contains":
        # 部分一致。match_value を文字列リテラルとして扱い regex 化。
        literal = _re.escape(patch.match_value)
        escaped = _escape_nginx_string(literal)
        return f'{nginx_var} ~ "{escaped}"'

    if patch.match_operator == "regex":
        # 生の正規表現をそのまま使う。エスケープは " のみ。
        # regex メタ文字 (\\s, \\d 等) は保持したいので re.escape はしない。
        escaped = _escape_nginx_string(patch.match_value)
        return f'{nginx_var} ~ "{escaped}"'

    return None


def _nginx_variable_for_match_type(match_type: str) -> str | None:
    """match_type に対応する nginx 組込変数を返す。未対応なら None。"""
    mapping = {
        "path": "$uri",
        "query": "$args",
        "method": "$request_method",
        # header / body は別処理（上位で早期 return している）
    }
    return mapping.get(match_type)


def _escape_nginx_string(value: str) -> str:
    """
    nginx の "..." 内に埋め込む文字列をエスケープする。

    - ダブルクォート: "  → \\"  （文字列終端と衝突しないため）
    - バックスラッシュはそのまま通す

    バックスラッシュを残す理由:
        nginx の正規表現マッチ ~ / ~* の右辺では、\\s や \\. などの
        正規表現メタ文字がそのまま regex エンジンに渡される仕様。
        既存の basic-rules.conf でも "UNION\\s+SELECT" のように
        バックスラッシュを直書きしている。
        ここで \\ → \\\\ にエスケープすると regex の意味が壊れる。
    """
    return value.replace('"', '\\"')


# ─── 内部: アクション本体の構築 ──────────────────────────
def _build_action_body(patch: PatchProposal) -> list[str]:
    """action に応じた nginx 文のリストを返す（if ブロック内に並べる）。"""
    escaped_rule_id = _escape_nginx_string(patch.rule_id)

    if patch.action == "block":
        return [
            "set $waf_block 1;",
            f'set $waf_reason "{escaped_rule_id}";',
        ]

    if patch.action == "log":
        return [
            f'set $waf_log_reason "{escaped_rule_id}";',
            "access_log /var/log/nginx/waf-log.log json_log;",
        ]

    if patch.action == "advisory":
        # advisory は enforce しない。観察・記録のみ。
        return [
            "# advisory: 観察のみ、ブロックしない",
            f'set $waf_advisory "{escaped_rule_id}";',
            "access_log /var/log/nginx/waf-advisory.log json_log;",
        ]

    if patch.action == "rate_limit":
        # rate_limit は本来 limit_req_zone + limit_req を http/location レベルで
        # 定義する必要があるため、if 文内では完結しない。教材としてマーカーのみ残す。
        return [
            "# rate_limit: http レベルで limit_req_zone 定義が別途必要",
            f'set $waf_rate_limit "{escaped_rule_id}";',
        ]

    # 未知アクション: フォールバック
    return [f"# 未対応 action: {patch.action}"]


# ─── 内部: snippet の組み立て ────────────────────────────
def _assemble_snippet(
    patch: PatchProposal,
    condition: str,
    action_body: list[str],
) -> str:
    """コメントヘッダ付きの完全な nginx if スニペットを生成する。"""
    # rationale は改行を含み得るので1行に正規化してコメントに入れる
    rationale_one_line = " ".join(patch.rationale_ja.split())

    lines = [
        f"# rule_id: {patch.rule_id}",
        f"# action: {patch.action} (confidence: {patch.confidence:.2f})",
        f"# target: {patch.target}",
        f"# rationale: {rationale_one_line}",
        f"if ({condition}) {{",
    ]
    for stmt in action_body:
        lines.append(f"    {stmt}")
    lines.append("}")
    return "\n".join(lines)
