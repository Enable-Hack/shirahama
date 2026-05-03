"""
ai-agent.backends.claude_backend

Anthropic Claude (Haiku 4.5) を用いた判断層実装。

この backend は:
    - 受信シグナルを JSON として整形
    - Claude に PatchProposal の JSON 列として提案を求める
    - 応答を PatchProposal に戻す（型検査は validator に委ねる）

再現性配慮:
    - temperature=0 で確率性を最小化
    - system prompt は固定（プロンプトキャッシュ適合）
    - 日本語出力を明示指示（簡体字混入等の事故抑止）

教材上の注意:
    - この backend は tool calling を使わず、プロンプトベースの
      JSON 出力のみで動く。受講者が中身を追いやすくするため。
    - 出力を直接使わず、必ず validator.validate_patches() を通すこと。
"""
from __future__ import annotations

import json
import os
from typing import Any

from anthropic import Anthropic

from ..llm import (
    LLMBackend,
    PatchProposal,
    Signal,
)
from ..prompts import BACKEND_SYSTEM_PROMPT_JA

DEFAULT_MODEL = "claude-haiku-4-5-20251001"

class ClaudeBackend(LLMBackend):
    """
    Anthropic Claude を用いた判断層実装。
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        api_key: str | None = None,
    ) -> None:
        self.model = model
        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY が設定されていません。"
                "環境変数に設定するか、ClaudeBackend(api_key=...) で渡してください。"
            )
        self.client = Anthropic(api_key=resolved_key)
        self._last_summary: str = ""

    def name(self) -> str:
        return f"claude:{self.model}"

    def propose_patches(
        self,
        signals: list[Signal],
        unmatched_logs: list[dict] | None = None,
        preflight_context: dict | None = None,
    ) -> list[PatchProposal]:
        if not signals and not unmatched_logs:
            self._last_summary = "新規に検知された異常はありません。"
            return []

        user_message = self._format_user_message(signals, unmatched_logs, preflight_context)
        response = self.client.messages.create(
            model=self.model,
            max_tokens=2048,
            temperature=0.0,  # 再現性重視
            system=BACKEND_SYSTEM_PROMPT_JA,
            messages=[{"role": "user", "content": user_message}],
        )

        text = _extract_text(response)
        payload = _parse_json_strict(text)

        self._last_summary = payload.get("summary_ja", "")
        patches_raw = payload.get("patches", [])

        patches: list[PatchProposal] = []
        for raw in patches_raw:
            patches.append(_to_patch_proposal(raw))
        return patches

    def explain_to_operator_ja(
        self,
        signals: list[Signal],
        patches: list[PatchProposal],
        unmatched_logs: list[dict] | None = None,
    ) -> str:
        if self._last_summary:
            return self._last_summary
        # propose_patches が呼ばれていない場合のフォールバック
        return (
            f"Claude ({self.model}) による判定: "
            f"シグナル {len(signals)} 件、未分類ログ {len(unmatched_logs or [])} 件、提案 {len(patches)} 件。"
        )

    def _format_user_message(
        self,
        signals: list[Signal],
        unmatched_logs: list[dict] | None = None,
        preflight_context: dict | None = None,
    ) -> str:
        signals_json = json.dumps(
            [
                {
                    "type": s.type,
                    "path": s.path,
                    "severity": s.severity,
                    "evidence": s.evidence,
                    "timestamp": s.timestamp,
                }
                for s in signals
            ],
            ensure_ascii=False,
            indent=2,
        )

        unmatched_json = ""
        if unmatched_logs:
            # Token 節約のため、最大 50 件に制限
            unmatched_logs = unmatched_logs[:50]
            unmatched_json = json.dumps(unmatched_logs, ensure_ascii=False, indent=2)

        msg = (
            "以下のシグナル列と、観測層をすり抜けた未分類の生ログを判定し、適切な PatchProposal を提案してください。\n"
            "JSON形式のみで応答してください。前置き・後置きは不要です。\n"
            "未分類ログの中に攻撃の意図（例: 大量のPOSTアクセスや未知の脆弱性スキャン）が推定できるものがあれば、それに対する提案も含めてください。\n\n"
            "【シグナル列】\n"
            f"{signals_json}\n"
        )
        if unmatched_json:
            msg += f"\n【未分類ログ (最大50件)】\n{unmatched_json}\n"

        if preflight_context:
            # /preflight が捉えた直前の異常 (サービス落ち / /etc 直近変更 / 不審ポート 等) を
            # Claude に渡し、シグナルとの整合性判断のヒントにさせる
            preflight_json = json.dumps(preflight_context, ensure_ascii=False, indent=2)
            msg += (
                "\n【受電直前の preflight 異常 (直前の状態スナップショット)】\n"
                "下記は受電直前に観測された異常です。シグナル列と矛盾しないか、また、\n"
                "「サービス落ち」「/etc 配下の直近変更」「不審 listen ポート」が攻撃と整合する場合は、\n"
                "改ざん/侵害の可能性として扱い、提案根拠 (rationale_ja) に明示してください。\n"
                f"{preflight_json}\n"
            )

        return msg


# ─── JSON 抽出・パース ──────────────────────────────────
def _extract_text(response: Any) -> str:
    """Anthropic API 応答からテキストブロックを結合して取り出す。"""
    chunks: list[str] = []
    for block in response.content:
        if getattr(block, "type", None) == "text":
            chunks.append(block.text)
    return "\n".join(chunks)


def _parse_json_strict(text: str) -> dict:
    """
    LLM 応答から JSON を抽出。コードフェンス除去等の最小限の救済のみ行う。
    過度に寛容にしない（教材的には「LLMに正しい形式で返させる」姿勢）。
    """
    text = text.strip()

    # 最小限のコードフェンス救済（```json ... ``` の形式）
    if text.startswith("```"):
        # 最初の ``` とその直後の言語指定を剥がす
        lines = text.splitlines()
        if len(lines) >= 2:
            lines = lines[1:]  # ```json 行を削除
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Claude 応答を JSON としてパースできませんでした: {exc}\n"
            f"応答先頭200文字: {text[:200]!r}"
        ) from exc


def _safe_float(value, default: float = 0.0) -> float:
    """
    LLM 応答の confidence など、型が保証されない値を安全に float 化する。

    - 数値: そのまま float
    - 数値文字列 "0.85": float 変換成功
    - "high" などの非数値文字列: default を返す
    - None: default を返す

    目的: backend 層で例外を投げて patcher を巻き添えにしない。
    確信度の妥当性（0.0〜1.0 の範囲）は validator 層で最終判定する。
    """
    if value is None:
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def _safe_str(value, default: str = "") -> str:
    """
    LLM 応答の文字列フィールドを安全に str 化する。

    重要: 素朴な str(raw.get(..., "")) だと、raw が {"rule_id": None} の場合
    str(None) = "None" という 4 文字の文字列になってしまう。これは
    validator の rule_id 形式（4〜64 文字、英数字・ハイフン・アンダースコア）を
    偶然通ってしまう危険がある。また target/match_value の空文字チェックも
    すり抜けてしまう。

    そのため None は default（通常は空文字）に、str でないものは str 化
    してから返す設計にする。
    """
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


def _to_patch_proposal(raw: dict) -> PatchProposal:
    """
    dict → PatchProposal。

    文字列・None などの形式不正は backend 層で既定値に正規化し、
    値の妥当性（0.0〜1.0 の範囲、Literal 許容値、regex 妥当性等）は
    後段の validator で検証する。これにより 1 件の不正値が
    backend 全体を落とさず、validator の all-or-nothing で弾かれる。
    """
    return PatchProposal(
        rule_id=_safe_str(raw.get("rule_id")),
        target=_safe_str(raw.get("target")),
        match_type=raw.get("match_type", ""),  # type: ignore[arg-type]
        match_operator=raw.get("match_operator", ""),  # type: ignore[arg-type]
        match_value=_safe_str(raw.get("match_value")),
        action=raw.get("action", ""),  # type: ignore[arg-type]
        confidence=_safe_float(raw.get("confidence"), 0.0),
        rationale_ja=_safe_str(raw.get("rationale_ja")),
    )
