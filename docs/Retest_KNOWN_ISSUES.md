# LoomMode 2.0.0 — known findings and limits

| Finding | Disposition |
| --- | --- |
| Historical input identity | Earlier rc.1 builds had distinct bytes under the same label; current package is identified by its own manifest and ZIP hashes. No transmission corruption is inferred. |
| Historical packaged test layout | Existing namespace checks and delivered-layout regression cover the old mismatch; do not apply old repairs blindly. |
| Historical P012 timeout/UNKNOWN | Exact original service/auth/profile cause is unverified. No refund, replay, provider switch or new retry follows. |
| Transport observations | HTTP_FALLBACK_SEEN / REQUEST_TIMEOUT_SEEN were nonblocking in a successful bounded run; no root-cause fix is claimed. |
| Manual/no-Git operation | Select automatic=false on first START. After TASK_ACCEPTED at COMMIT_AUTHORIZATION stop advancing and close normally. Git false is not an automatic wait switch. |
| Device and version scope | Windows/Codex-only limited evidence; second physical-device identity not independently proved. Arbitrary versions, platforms and devices are unverified. |
| Larger workflows | General recovery, existing-project migration and unattended multi-Task engineering are outside the first support promise. |
| Audit detail | Original native command bodies are incomplete; local relay is not platform delivery authentication. |
| Release and Binding | This candidate is not yet Owner accepted or publicly released. No accepted-release Binding or old State/Grant migration is granted. |

Current 2.0.0 documents and wheel are a new build with the current public role
projections and Prompt text. Historical rc.3/rc.2 files remain frozen. Offline
checks establish only their actual scope; no new live model or cross-device run
is implied. Preserve unknown effects and original evidence before any lawful
follow-up. Never replay an ambiguous request, reset accounting, change shared
ACL/registry or bypass a safety refusal to obtain a PASS.
