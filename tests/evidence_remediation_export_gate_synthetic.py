"""Pure offline, synthetic export-shape reference; never a production authorization check.

The trusted context here is illustrative, not authenticated. Self-reported
approved/redacted flags cannot prove review or actual safe redaction.
"""

def eligible(record, *, tenant, review):
    if type(tenant) is not str or not tenant.strip():
        return False
    if type(review) is not str or not review.strip():
        return False
    if type(record) is not dict:
        return False
    keys = {"tenant", "review", "finding", "remediation", "digest", "redacted", "approved"}
    if set(record) != keys:
        return False
    identities = ("tenant", "review", "finding", "remediation", "digest")
    if any(type(record[k]) is not str or not record[k].strip()
           or record[k] != record[k].strip() for k in identities):
        return False
    if record["tenant"] != tenant or record["review"] != review:
        return False
    if type(record["redacted"]) is not bool or record["redacted"] is not True:
        return False
    if type(record["approved"]) is not bool or record["approved"] is not True:
        return False
    digest = record["digest"]
    return len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
