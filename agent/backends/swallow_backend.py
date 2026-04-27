"""
ai-agent.backends.swallow_backend

Ollama 経由で Llama 3.1 Swallow 8B などのローカル LLM を利用する判断層実装。

設計:
    - Ollama REST API (/api/chat) を直接叩く
    - anthropic SDK は不要。依存は requests のみ（既に存在）
    - Claude と同じ system prompt を使い、モデル差のみを浮かび上がらせる
    - format='json' でレスポンスを JSON に強制（Ollama の機能で小型モデルでも安定化）
    - temperature=0 で再現性重視

環境変数:
    OLLAMA_BASE_URL  Ollama サーバ URL
                     (default: http://localhost:11434)
    OLLAMA_MODEL     使用モデル名
                     (default: 本命 Llama-3.1-Swallow-8B-Instruct-v0.2 Q4_K_M)
    OLLAMA_TIMEOUT   推論タイムアウト秒数
                     (default: 120 — CPU 推論は遅いことがあるため長め)

教材上の位置づけ:
    - 閉域演習用（Day 2）: クラウド LLM が使えない環境での代替
    - Claude との比較対象: 日本語ネイティブ訓練モデルの挙動確認
    - 「LLM は差し替え可能」の実証

設計方針（レビュー指摘）:
    backend 本体は接続失敗時に明示的な例外を投げる。
    Mock へのフォールバックは demo.py などのアプリ層の責務とする。
    これにより、実運用コードで失敗原因の追跡が可能になる。
"""
from __future__ import annotations

import json
import os
from typing import Any

import requests

from ..llm import LLMBackend, PatchProposal, Signal
from ..prompts import BACKEND_SYSTEM_PROMPT_JA

DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = (
    "hf.co/mradermacher/Llama-3.1-Swallow-8B-Instruct-v0.2-i1-GGUF:Q4_K_M"
)
DEFAULT_OLLAMA_TIMEOUT = 120.0  # 秒


# ─── 例外階層 ─────────────────────────────────────────
class OllamaError(Exception):
    """SwallowBackend の基底例外。"""


class OllamaConnectionError(OllamaError):
    """Ollama サーバへの接続に失敗した。"""


class OllamaModelNotFoundError(OllamaError):
    """指定モデルが Ollama に pull されていない。"""


class OllamaTimeoutError(OllamaError):
    """推論がタイムアウトした。"""


class SwallowBackend(LLMBackend):
    """
    Ollama を経由してローカル LLM を呼び出す backend。

    デフォルトは Llama 3.1 Swallow 8B だが、
    `model` 引数または OLLAMA_MODEL で任意のモデルに切り替え可能
    （例: qwen2.5:7b-instruct）。
    """

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self.model = model or os.environ.get("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
        raw_url = (
            base_url
            or os.environ.get("OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL)
        )
        self.base_url = raw_url.rstrip("/")
        self.timeout = float(
            timeout
            if timeout is not None
            else os.environ.get("OLLAMA_TIMEOUT", DEFAULT_OLLAMA_TIMEOUT)
        )
        self._last_summary: str = ""

    def name(self) -> str:
        # モデル名が長大な HF パス形式の場合は末尾を抜き出して短く表示
        short = self.model.rsplit("/", 1)[-1] if "/" in self.model else self.model
        return f"swallow:{short}"

    # ─── 事前疎通確認 ────────────────────────────────────
    def check_connection(self) -> None:
        """
        Ollama サーバへの接続可能性とモデルの存在を事前確認する。

        成功: None を返す
        失敗: 原因別の例外（OllamaConnectionError / OllamaModelNotFoundError 等）

        demo.py などのアプリ層が「Ollama が使えるか先に確かめて、
        ダメなら Mock に切り替える」ためのフック。
        """
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5.0)
            resp.raise_for_status()
        except requests.ConnectionError as exc:
            raise OllamaConnectionError(
                f"Ollama サーバに接続できません ({self.base_url})。"
                "Ollama が起動しているか確認してください。"
                "手順は SETUP_OLLAMA.md を参照してください。"
            ) from exc
        except requests.Timeout as exc:
            raise OllamaTimeoutError(
                f"Ollama サーバが応答しません ({self.base_url})。"
            ) from exc
        except requests.RequestException as exc:
            raise OllamaError(f"Ollama API エラー: {exc}") from exc

        # モデル存在チェック
        try:
            models_data = resp.json()
        except ValueError as exc:
            raise OllamaError(
                f"Ollama /api/tags の応答が JSON ではありません"
            ) from exc

        available = {m.get("name", "") for m in models_data.get("models", [])}
        if self.model not in available:
            raise OllamaModelNotFoundError(
                f"指定モデル '{self.model}' が Ollama に pull されていません。\n"
                f"以下のコマンドで pull してください:\n"
                f"    ollama pull {self.model}\n"
                f"現在利用可能なモデル: "
                f"{sorted(m for m in available if m) or '(なし)'}"
            )

    # ─── 提案生成 ────────────────────────────────────────
    def propose_patches(self, signals: list[Signal]) -> list[PatchProposal]:
        if not signals:
            self._last_summary = "新規に検知された異常はありません。"
            return []

        user_message = self._format_user_message(signals)
        response_text = self._call_ollama(user_message)
        payload = _parse_json_lenient(response_text)

        self._last_summary = payload.get("summary_ja", "")
        patches_raw = payload.get("patches", [])
        return [_to_patch_proposal(raw) for raw in patches_raw]

    def explain_to_operator_ja(
        self,
        signals: list[Signal],
        patches: list[PatchProposal],
    ) -> str:
        if self._last_summary:
            return self._last_summary
        return (
            f"Swallow ({self.model}) による判定: "
            f"シグナル {len(signals)} 件、提案 {len(patches)} 件。"
        )

    # ─── 内部処理 ────────────────────────────────────────
    def _call_ollama(self, user_message: str) -> str:
        """Ollama /api/chat を呼び出して応答テキストを返す。"""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": BACKEND_SYSTEM_PROMPT_JA},
                {"role": "user", "content": user_message},
            ],
            # Ollama の JSON 強制機能。小型モデルでの出力安定化に有効。
            "format": "json",
            "options": {
                "temperature": 0.0,
                "num_predict": 2048,
            },
            "stream": False,
        }
        try:
            resp = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout,
            )
        except requests.ConnectionError as exc:
            raise OllamaConnectionError(
                f"Ollama サーバに接続できません ({self.base_url})。"
            ) from exc
        except requests.Timeout as exc:
            raise OllamaTimeoutError(
                f"Ollama 推論がタイムアウトしました ({self.timeout} 秒)。"
                "OLLAMA_TIMEOUT 環境変数で上限を延長できます。"
            ) from exc

        # HTTP ステータスチェック
        if resp.status_code == 404:
            raise OllamaModelNotFoundError(
                f"モデル '{self.model}' が見つかりません。"
                f"'ollama pull {self.model}' を実行してください。"
            )
        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            raise OllamaError(
                f"Ollama HTTP エラー ({resp.status_code}): {resp.text[:300]}"
            ) from exc

        try:
            data = resp.json()
        except ValueError as exc:
            raise OllamaError(
                f"Ollama 応答が JSON ではありません: {resp.text[:200]!r}"
            ) from exc

        return data.get("message", {}).get("content", "")

    def _format_user_message(self, signals: list[Signal]) -> str:
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
        return (
            "以下のシグナル列を判定し、適切な PatchProposal を提案してください。\n"
            "JSON形式のみで応答してください。前置き・後置きは不要です。\n\n"
            "【シグナル列】\n"
            f"{signals_json}"
        )


# ─── JSON パース（ローカルモデル用に寛容） ───────────────
def _parse_json_lenient(text: str) -> dict:
    """
    ローカルモデルの出力から JSON を抽出する。

    format='json' を指定していても、稀に前置きやコードフェンスが混入する
    ことがあるため、段階的に救済を試みる。救済順:
        1. 素直に json.loads
        2. コードフェンス剥がし
        3. 最初の { から最後の } までを抽出

    いずれも失敗したら ValueError を投げる（backend 本体の責務として
    「失敗は正直に投げる」を守る）。
    """
    if not text or not text.strip():
        raise ValueError("Swallow 応答が空でした")

    # Phase 1: そのまま
    stripped = text.strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # Phase 2: コードフェンス剥がし
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 2:
            lines = lines[1:]  # ```json 行を除去
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            candidate = "\n".join(lines).strip()
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

    # Phase 3: 最外 JSON オブジェクト抽出
    first = text.find("{")
    last = text.rfind("}")
    if first != -1 and last > first:
        candidate = text[first:last + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Swallow 応答を JSON としてパースできませんでした: {exc}\n"
                f"応答先頭200文字: {text[:200]!r}"
            ) from exc

    raise ValueError(
        f"Swallow 応答から JSON を抽出できませんでした。\n"
        f"応答先頭200文字: {text[:200]!r}"
    )


def _safe_float(value, default: float = 0.0) -> float:
    """
    LLM 応答の confidence など、型が保証されない値を安全に float 化する。

    - 数値: そのまま float
    - 数値文字列 "0.85": float 変換成功
    - "high" などの非数値文字列: default を返す
    - None: default を返す

    ローカル LLM は Ollama の format=json 指定でも、稀に "high" や null
    を confidence に入れて返すことがある。backend 層で落ちないよう
    正規化し、値の妥当性（0.0〜1.0 の範囲）は validator で最終判定する。
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
    後段の validator で検証する。ローカル LLM は Claude よりも
    出力の型がぶれやすいため、ここでの正規化は実用上重要。
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
