"""
ai-agent.patcher

判断 → 検証 → レンダリング → 永続化 の統合オーケストレータ。

パイプライン:
    1. 観測層 (analyzer.py) から list[Signal] を受け取る
    2. backend.propose_patches(signals) で判断
    3. validator.validate_patches(patches) で検証
    4. renderers.render_patches(patches) でレンダリング
    5. temp_rules.json に結果を書き出す
    6. オペレータ向け説明を生成

設計原則:
    - backend 本体は失敗を正直に投げる
    - 検証失敗時は renderer に渡さず temp_rules.json に検証エラーを記録
    - どの段階で何が起きたかを PatcherRunSummary として返す
      （監査・ロギング・次段処理のための情報）

教材上の位置づけ:
    「観測→判断→検証→実行」の4層分離がそのままコードに現れている。
    LLM 出力の部分採用（一部通す・一部弾く）は事故の温床なので、
    all-or-nothing で処理する（validator に従う）。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .llm import LLMBackend, Signal
from .renderers import RenderResult, render_patches
from .validator import PatchValidationError, validate_patches


DEFAULT_OUTPUT_PATH = "temp_rules.json"


@dataclass
class PatcherRunSummary:
    """
    1回の patcher.process() 実行結果のサマリ。

    呼出側はこのオブジェクトを見て何が起きたかを理解する:
        - validation_passed=False → 検証失敗、rendered 件数は 0
        - rendered_count 件の rule が temp_rules.json の "rules" に入った
        - advisory_count 件の rule が "advisories" に入った
        - skipped_count 件は nginx で表現できなかった
    """
    backend_name: str
    signal_count: int
    patches_proposed: int
    validation_passed: bool
    validation_error: str | None
    rendered_count: int
    advisory_count: int
    skipped_count: int
    explanation_ja: str
    output_path: str


class Patcher:
    """
    Signal 列を受け取って backend/validator/renderer を連携させ、
    temp_rules.json に結果を書き出すオーケストレータ。
    """

    def __init__(
        self,
        backend: LLMBackend,
        output_path: str | Path = DEFAULT_OUTPUT_PATH,
    ) -> None:
        self.backend = backend
        self.output_path = Path(output_path)

    def process(self, signals: list[Signal]) -> PatcherRunSummary:
        """
        パイプライン全体を実行し、結果を temp_rules.json に書き出す。
        """
        # ─── 判断層 ─────────────────────────────────────
        patches = self.backend.propose_patches(signals)

        # ─── 検証層 ─────────────────────────────────────
        validation_error: str | None = None
        render_results: list[RenderResult] = []
        try:
            validate_patches(patches)
            validation_passed = True
        except PatchValidationError as exc:
            validation_passed = False
            validation_error = str(exc)
            # 検証失敗時は renderer に渡さない（部分採用はしない）

        # ─── レンダリング層 ─────────────────────────────
        if validation_passed:
            render_results = render_patches(patches)

        # ─── 結果の分類 ─────────────────────────────────
        rendered_rules: list[RenderResult] = []
        advisory_rules: list[RenderResult] = []
        skipped_rules: list[RenderResult] = []
        for rr in render_results:
            if rr.status == "skipped":
                skipped_rules.append(rr)
            elif rr.patch.action == "advisory":
                advisory_rules.append(rr)
            else:
                rendered_rules.append(rr)

        # ─── 永続化 ─────────────────────────────────────
        output_data = {
            "metadata": {
                "backend": self.backend.name(),
                "signal_count": len(signals),
                "patches_proposed": len(patches),
                "validation_passed": validation_passed,
                "rendered_count": len(rendered_rules),
                "advisory_count": len(advisory_rules),
                "skipped_count": len(skipped_rules),
            },
            "rules": [_serialize(rr) for rr in rendered_rules],
            "advisories": [_serialize(rr) for rr in advisory_rules],
            "skipped": [_serialize(rr) for rr in skipped_rules],
        }
        if validation_error:
            output_data["validation_error"] = validation_error

        self.output_path.write_text(
            json.dumps(output_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        # ─── オペレータ向け説明 ─────────────────────────
        explanation = self.backend.explain_to_operator_ja(signals, patches)

        return PatcherRunSummary(
            backend_name=self.backend.name(),
            signal_count=len(signals),
            patches_proposed=len(patches),
            validation_passed=validation_passed,
            validation_error=validation_error,
            rendered_count=len(rendered_rules),
            advisory_count=len(advisory_rules),
            skipped_count=len(skipped_rules),
            explanation_ja=explanation,
            output_path=str(self.output_path),
        )


def _serialize(rr: RenderResult) -> dict:
    """RenderResult を temp_rules.json に書き出すための dict に変換する。"""
    return {
        "rule_id": rr.rule_id,
        "status": rr.status,
        "action": rr.patch.action,
        "target": rr.patch.target,
        "match": {
            "type": rr.patch.match_type,
            "operator": rr.patch.match_operator,
            "value": rr.patch.match_value,
        },
        "confidence": rr.patch.confidence,
        "rationale_ja": rr.patch.rationale_ja,
        "nginx_snippet": rr.nginx_snippet,
        "skip_reason": rr.skip_reason,
    }
