# Issue #894: legacy Finding render boundary

An isolated test-only acceptance run is expected RED on main dd4072cdd1a2bc44a752ccbb7b1d0b6d56559da1: `Finding.validate()` does not inspect evidence. No target access, no production code change, no merge. The canonical list[str] and empty-list fallback remain supported; list/str subclasses, nonstring and blank items must fail closed before reporting. Existing owner #100 retains `models.py` and #732 retains `reporting.py`.
