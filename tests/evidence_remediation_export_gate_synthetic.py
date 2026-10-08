"""Pure, synthetic, non-authoritative remediation export gate reference."""


def eligible(record, *, tenant, review):
    if type(tenant) is not str or not tenant or type(review) is not str or not review:
        return False
    if type(record) is not dict:
        return False
    keys = {"tenant", "review", "finding", "remediation", "digest", "redacted", "approved"}
    if set(record) != keys:
        return False
    if any(type(record[k]) is not str or not record[k] for k in ("tenant", "review", "finding", "remediation", "digest")):
        return False
    if record["tenant"] != tenant or record["review"] != review:
        return False
    if record["redacted"] is not True or type(record["redacted"]) is not bool:
        return False
    if record["approved"] is not True or type(record["approved"]) is not bool:
        return False
    digest = record["digest"]
    return len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
