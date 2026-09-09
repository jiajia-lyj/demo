Test file: tests/test_e2e_zero_shot.py
Sample: 1,000 real CVEs (NVD 2024 official CVSS v3.1 data)
## Results Summary
| Metric                              | Result | Target        | Status |
|--------------------------------------|--------|---------------|--------|
| DK fallback severity accuracy (zero-shot) | 0.553  | > 0.595 (WCL) | FAIL   |
| Full-vector exact match (zero-shot)  | 1.1%   | —             | LOW    |
| Crashes on real CVE data             | 14/1000| 0             | FAIL   |
| LLM enhancement effect on score      | none   | should change output | FAIL |
## Issues Found
### 1. Crash on real data — app/core/feature_extractor.py
VALUES["AV"] only has key "ADJACENT", but real NVD data uses
"ADJACENT_NETWORK". Causes KeyError on ~1.4% of CVEs.
FIX: add "ADJACENT_NETWORK" to VALUES["AV"].
### 2. Weak feature inference — app/core/feature_extractor.py
infer_features() keyword rules are inaccurate, especially for
confidentiality/integrity/availability (37-58% accuracy). This is why
zero-shot accuracy (0.553) misses the 0.595 baseline.
FIX: improve/expand keyword rules, or replace with a trained classifier.
### 3. LLM enhancement is a no-op — app/core/llm_enhancer.py + feature_extractor.py
LLM prompt asks for short keys (AV, AC, PR...) but infer_features() only
reads long-form keys (attack_vector, attack_complexity...). LLM output is
silently dropped; scores never change.
FIX: make key names match on both sides (translate short->long keys before
merging, or change the prompt to request long-form keys).
### 4. Data leakage in local-rule scoring — app/core/scheduler.py
_nvd_features() reads the official CVSS answer straight from the CVE's own
raw_data before scoring, making "local rule" scores look ~100% accurate.
Not a real result.
FIX: strip official CVSS fields from any data used for evaluation, or skip
_nvd_features() entirely in a dedicated zero-shot test mode.
