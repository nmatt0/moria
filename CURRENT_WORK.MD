# Current work

- 2026-09-09T23:42:57-05:00 — Started reviewing the repository for hard-to-understand wording. Confirmed a clean `master` branch at `7630f8d` and found no earlier work journal.
- 2026-09-09T23:49:41-05:00 — Created and switched to `docs/plain-language-copy`. Rewrote the README, license notes, firmware rule descriptions, and the tool that creates those descriptions.
- 2026-09-10T00:06:41-05:00 — Extended the plain-language pass to the manual, command help, reports, warnings, build notes, import tools, and test descriptions. Kept exact command names, JSON names, file-format names, and license names where changing them would change the meaning.
- 2026-09-10T00:13:06-05:00 — Verified the manual, Python files, branch diff, rebuilt successfully with optional compression support, and passed 86 unit checks plus sample, byte-copying, descrambling, and RFP checks. The full unpacking check passed all available cases; its three zstd cases could not run because this computer does not have the zstd development files.
