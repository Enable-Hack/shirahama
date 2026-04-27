"""
ai-agent: PatchProposal 検証層

renderer に渡す前に必ず通す関所。LLM や backend の出力は、
どれほど信頼できるモデルでも必ず検証層を通す、というのが本教材の原則。

これは性能問題ではなく、セキュリティ設計の基本原則である:
    - Function calling の引数バリデーション
    - SQL生成LLMの出力に対する allow-list チェック
    - コード生成LLMの出力に対する静的解析
    いずれも同じ思想に基づく。

教材メッセージ:
    「LLM出力を renderer に直接渡すな。必ず検証層を挟め」
"""
from __future__ import annotations

import re

from .llm import (
    ACTION_VALUES,
    MATCH_OPERATOR_VALUES,
    MATCH_TYPE_VALUES,
    PatchProposal,
)


class PatchValidationError(ValueError):
    """PatchProposal の検証失敗時に送出される例外。"""


# ReDoS 簡易検出: ネスト量化子や catastrophic backtracking の初歩パターン
# 完全な検出は不可能だが、教材用途では代表的な地雷を弾けば十分
_REDOS_SUSPICIOUS = re.compile(
    r"(\([^)]*[+*]\)[+*])|(\([^)]*\|[^)]*\)[+*])"
)

# rule_id は ASCII 英数字 + ハイフン + アンダースコアのみ、4〜64文字
_RULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{4,64}$")

_MAX_MATCH_VALUE_LEN = 512
_MIN_RATIONALE_LEN = 10


def validate_patch(patch: PatchProposal) -> None:
    """
    1件の PatchProposal を検証する。不正なら PatchValidationError を送出。

    検証項目:
        - rule_id の形式（英数字・ハイフン・アンダースコア 4〜64文字）
        - match_type / match_operator / action の enum 適合性
        - target / match_value / rationale_ja の空文字禁止
        - confidence の範囲 [0.0, 1.0]
        - regex operator の場合: コンパイル可能性、ReDoS 疑いパターン検出
        - match_value の長さ上限（512字）
        - rationale_ja の最小長（10字）
    """
    # ─── rule_id ──────────────────────────────────────
    if not _RULE_ID_PATTERN.match(patch.rule_id):
        raise PatchValidationError(
            f"rule_id の形式が不正です: {patch.rule_id!r} "
            f"(許容: ASCII英数字・ハイフン・アンダースコア 4〜64文字)"
        )

    # ─── enum 適合性 ──────────────────────────────────
    if patch.match_type not in MATCH_TYPE_VALUES:
        raise PatchValidationError(
            f"match_type が不正です: {patch.match_type!r} "
            f"(許容値: {MATCH_TYPE_VALUES})"
        )
    if patch.match_operator not in MATCH_OPERATOR_VALUES:
        raise PatchValidationError(
            f"match_operator が不正です: {patch.match_operator!r} "
            f"(許容値: {MATCH_OPERATOR_VALUES})"
        )
    if patch.action not in ACTION_VALUES:
        raise PatchValidationError(
            f"action が不正です: {patch.action!r} "
            f"(許容値: {ACTION_VALUES})"
        )

    # ─── 空文字禁止 ───────────────────────────────────
    if not patch.target.strip():
        raise PatchValidationError("target が空です")
    if not patch.match_value.strip():
        raise PatchValidationError("match_value が空です")
    if not patch.rationale_ja.strip():
        raise PatchValidationError("rationale_ja が空です")

    # ─── 長さ制限 ─────────────────────────────────────
    if len(patch.match_value) > _MAX_MATCH_VALUE_LEN:
        raise PatchValidationError(
            f"match_value が長すぎます: {len(patch.match_value)} 文字 "
            f"(上限: {_MAX_MATCH_VALUE_LEN})"
        )
    if len(patch.rationale_ja.strip()) < _MIN_RATIONALE_LEN:
        raise PatchValidationError(
            f"rationale_ja が短すぎます（{_MIN_RATIONALE_LEN} 文字以上必要）"
        )

    # ─── confidence 範囲 ──────────────────────────────
    if not isinstance(patch.confidence, (int, float)):
        raise PatchValidationError(
            f"confidence は数値である必要があります: {patch.confidence!r}"
        )
    if not (0.0 <= float(patch.confidence) <= 1.0):
        raise PatchValidationError(
            f"confidence が範囲外です: {patch.confidence} (0.0 〜 1.0)"
        )

    # ─── regex operator の追加検証 ────────────────────
    if patch.match_operator == "regex":
        try:
            re.compile(patch.match_value)
        except re.error as exc:
            raise PatchValidationError(
                f"regex がコンパイルできません: {exc} (value={patch.match_value!r})"
            ) from exc

        if _REDOS_SUSPICIOUS.search(patch.match_value):
            raise PatchValidationError(
                f"regex に ReDoS 疑いのパターンが含まれています: "
                f"{patch.match_value!r}"
            )


def validate_patches(patches: list[PatchProposal]) -> list[PatchProposal]:
    """
    パッチ列を一括検証する。全件妥当ならそのまま返す。
    1件でも不正があれば例外を送出（all-or-nothing）。

    教材ポイント:
        「一部だけ通す」運用は LLM 出力の場合に事故の温床になる。
        renderer に渡すなら全件健全、そうでなければ全件差し戻して
        観測層・記録層に残す、が安全。
    """
    for i, p in enumerate(patches):
        try:
            validate_patch(p)
        except PatchValidationError as exc:
            raise PatchValidationError(
                f"patch[{i}] (rule_id={p.rule_id!r}) の検証失敗: {exc}"
            ) from exc
    return patches
