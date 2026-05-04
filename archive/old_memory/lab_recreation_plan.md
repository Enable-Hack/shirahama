---
name: Whiskey lab recreation plan on OCI
description: Goal and step plan for rebuilding the whiskey lab services on OCI (bravo + victor + attack-vm) so the AI log analysis pipeline can be tested end-to-end. Read when working on lab service installation or attack scenario testing.
type: project
originSessionId: f118aa6f-295b-4aa6-91c5-ec37daa58e41
---
**Goal (deadline: 2026-05-02):** Have a working end-to-end pipeline where attacks from `attack-vm` produce logs on `bravo`/`victor` that `agent/analyzer.py` correctly classifies. The deliverable is `docs/21_システム解説.md` reflecting an actually-runnable system, not a paper design.

**Why:** Right now docs describe a system that has only been partially tested in pieces. The on-prem lab (whiskey) is gone or unreliable; OCI is the new substrate.

**Reference (do not upload anywhere):** `docs/参加者配布資料_whiskey.pdf` — the closest thing to the original target architecture. Match this when in doubt about service versions / configs.

**How to apply (work plan):**
1. Audit what each server actually has installed (the user noted "勝手にインストールしているもの" exist) — both bravo and victor are fresh Rocky 8 stock images, so this means inventorying what the original whiskey lab had and reproducing it.
2. Map attack scenarios to servers definitively. Currently `.claude/commands/` (ddos/dns-tamper/phishing/ransomware/wp-tamper) define scenarios but the bravo-vs-victor target mapping is not yet locked down — user said this is "まだしっかりと調べられていない".
3. Install services per role:
   - **bravo (Rocky 8)**: BIND with deliberately permissive `allow-update`, Sendmail+Courier, Apache+PHP user dirs, MySQL.
   - **victor (Rocky 8)**: Apache + WordPress 4.9.4 + RainLoop 1.12.0 (intentionally EOL for known CVEs), Sendmail+Courier, ISC DHCP, rsyslog hub receiving from bravo + attack-vm.
   - **attack-vm (Ubuntu)**: install attacker tooling (curl, nmap, dnsutils, hydra, msf optional).
4. Update `agent/backends/mock_backend.py` whitelisted IPs from the on-prem 10.1.11.50-99 range to OCI private IPs of attack-vm.
5. Update preprocess scripts for Rocky log paths (bravo was FreeBSD originally; paths differ).
6. Run scenarios one-by-one. Recommended order: `wp-tamper` → `dns-tamper` → `phishing` → `ddos` → `ransomware`. Validate analyzer output at each step.

**Open decisions to revisit:**
- Whether to retry FreeBSD on bravo using a custom image with pre-baked SSH key (the user accepted Rocky as final-for-now, but the docs assume FreeBSD-style paths).
- Capacity: 1GB RAM on bravo may force trimming to BIND-only or split services across more hosts.
