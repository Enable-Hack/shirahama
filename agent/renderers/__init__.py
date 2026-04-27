"""
ai-agent.renderers: PatchProposal を各 WAF の固有構文に変換するレンダラ群

利用可能なレンダラ:
    - nginx_renderer: nginx の if 文構文へ変換

将来的に:
    - modsec_renderer: ModSecurity SecRule 構文
    - envoy_renderer:  Envoy HTTP filter 設定
    などを追加可能な設計。

教材上の位置づけ:
    LLM が直接 nginx 記法を書く設計は ReDoS や構文エラーの温床。
    中立表現（PatchProposal）を経由してレンダラが構文化することで、
    判断層（LLM）と実行層（WAF）の関心を分離する。
"""
from .nginx_renderer import (
    RenderResult,
    render_patch,
    render_patches,
)

__all__ = ["RenderResult", "render_patch", "render_patches"]
