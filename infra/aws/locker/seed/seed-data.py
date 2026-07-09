#!/usr/bin/env python3
"""
seed-data.py — synthetic multi-tenant seed data for the Locker breadth demo.

SEEDED / SYNTHETIC ARTIFACT — every identifier, email, and secret value below
is obviously synthetic placeholder material authored for this engagement.
Nothing here resembles, references, or was derived from real credentials,
real people, or a real Locker/Bitwarden-lineage vault. Cross-reference:
LOCKER-SPEC.md §1.3 (tenancy model) and §2 (seed mechanism).

This script is pure generation: no network calls, no dependency on a live
Locker/MySQL instance. Re-running it deterministically re-emits the same
fixture. Default output is a JSON fixture (easiest to review + diff); pass
--sql to instead emit MySQL-flavored INSERT statements matching core-api's
Bitwarden-lineage schema shape (users / ciphers / collections /
collection_users) for whoever wires up the actual seeded MySQL instance at
build day.

Tenants (exact ranges per LOCKER-SPEC.md §1.3):
  U-A  alice@acme.test    — ciphers c1001-c1010  — VICTIM tenant. The seeded
                             IDOR (seed-idor.patch) exposes these ciphers to
                             U-B's session.
  U-B  bob@rival.test     — ciphers c2001-c2010  — ATTACKER's own valid,
                             authenticated account. hacker-bob's WEB pack
                             authenticates AS U-B and walks the cipher_id
                             range; U-B's own ciphers are not part of the
                             finding, only the vehicle for the authenticated
                             session.
  U-C  carol@control.test — ciphers c3001-c3010  — CONTROL TENANT. Not
                             attacked, never part of the seeded defect.
                             Every probe against U-C's resources — under any
                             endpoint, including the seeded one — must return
                             a correct authorization denial. If any report
                             flags a U-C resource as vulnerable, that is a
                             graded FALSE POSITIVE, not partial credit. See
                             LOCKER-SPEC.md §2.3.
  TEAM-1                   — shared ciphers s5001-s5005 — members U-A and
                             U-C ONLY. U-B is deliberately NOT a member; this
                             is what the §2.2 fallback variant (sharing
                             membership check) would expose if it were the
                             live seed instead of the primary §2.1 variant.

Cipher IDs are sequential/enumerable surrogate keys (never UUIDs), matching
LOCKER-SPEC.md §1.3's explicit statement that this is a deliberate seed
property (walkability), not an oversight.
"""

import argparse
import json
import sys

# -----------------------------------------------------------------------
# Tenants
# -----------------------------------------------------------------------
# NOTE: U-C is the control tenant — it is NEVER attacked. Its ciphers exist
# solely so a probe against them can be graded as a correct denial (or a
# false positive, if some future report wrongly flags them).
USERS = [
    {
        "user_id": "U-A",
        "email": "alice@acme.test",
        "password_placeholder": "{{PLACEHOLDER_SECRET_U-A}}",
        "role": "victim",
        "note": "Owns c1001-c1010. The seeded IDOR (seed-idor.patch) exposes "
                "these to U-B's authenticated session.",
    },
    {
        "user_id": "U-B",
        "email": "bob@rival.test",
        "password_placeholder": "{{PLACEHOLDER_SECRET_U-B}}",
        "role": "attacker_own_account",
        "note": "Attacker's own valid, authenticated account. This is the "
                "calling identity hacker-bob's WEB pack uses; U-B's own "
                "ciphers (c2001-c2010) are not part of the finding.",
    },
    {
        "user_id": "U-C",
        "email": "carol@control.test",
        "password_placeholder": "{{PLACEHOLDER_SECRET_U-C}}",
        "role": "control_tenant_not_attacked",
        "note": "CONTROL TENANT — never attacked. Every probe against any "
                "U-C resource must return a correct authorization denial. "
                "Flagging a U-C resource as vulnerable is a graded false "
                "positive per LOCKER-SPEC.md §2.3.",
    },
]

# -----------------------------------------------------------------------
# Ciphers (per-tenant vault items, sequential/enumerable IDs by design)
# -----------------------------------------------------------------------
def _ciphers_for(owner_user_id, id_start, id_end, label):
    return [
        {
            "cipher_id": f"c{cid}",
            "owner_user_id": owner_user_id,
            "type": "login",
            "name": f"{label} synthetic item {cid}",
            "secret_placeholder": f"{{{{PLACEHOLDER_CIPHER_SECRET_c{cid}}}}}",
        }
        for cid in range(id_start, id_end + 1)
    ]


CIPHERS = (
    _ciphers_for("U-A", 1001, 1010, "alice@acme.test")
    + _ciphers_for("U-B", 2001, 2010, "bob@rival.test")
    + _ciphers_for("U-C", 3001, 3010, "carol@control.test")
)

# -----------------------------------------------------------------------
# TEAM-1 shared collection — members U-A and U-C ONLY. U-B is deliberately
# excluded; this is the precondition the §2.2 fallback seed variant relies on.
# -----------------------------------------------------------------------
TEAM_1 = {
    "team_id": "TEAM-1",
    "members": ["U-A", "U-C"],  # U-B intentionally NOT included
    "shared_ciphers": [
        {
            "share_id": f"s{sid}",
            "cipher_id": f"s{sid}",
            "team_id": "TEAM-1",
            "name": f"TEAM-1 shared synthetic item {sid}",
            "secret_placeholder": f"{{{{PLACEHOLDER_SHARED_SECRET_s{sid}}}}}",
        }
        for sid in range(5001, 5006)
    ],
}


def build_fixture():
    return {
        "_disclosure": (
            "SEEDED / SYNTHETIC fixture. Every user, cipher, and secret "
            "value in this file is placeholder data authored for this "
            "engagement. See LOCKER-SPEC.md §1.3 and seed/README.md."
        ),
        "users": USERS,
        "ciphers": CIPHERS,
        "team_1": TEAM_1,
    }


def emit_json():
    print(json.dumps(build_fixture(), indent=2, sort_keys=False))


def emit_sql():
    lines = [
        "-- SEEDED / SYNTHETIC data. See LOCKER-SPEC.md §1.3 and seed/README.md.",
        "-- Every value below is placeholder material; no real users, no real secrets.",
        "",
        "-- Users",
    ]
    for u in USERS:
        lines.append(
            "INSERT INTO users (user_id, email, password_hash) VALUES "
            f"('{u['user_id']}', '{u['email']}', '{u['password_placeholder']}');"
            f"  -- {u['role']}: {u['note']}"
        )

    lines.append("")
    lines.append("-- Ciphers (owner-scoped vault items)")
    for c in CIPHERS:
        lines.append(
            "INSERT INTO ciphers (cipher_id, owner_user_id, type, name, data) VALUES "
            f"('{c['cipher_id']}', '{c['owner_user_id']}', '{c['type']}', "
            f"'{c['name']}', '{c['secret_placeholder']}');"
        )

    lines.append("")
    lines.append("-- TEAM-1 shared collection (members: U-A, U-C only — U-B excluded)")
    lines.append(
        "INSERT INTO collections (team_id, name) VALUES ('TEAM-1', 'TEAM-1 shared collection');"
    )
    for member in TEAM_1["members"]:
        lines.append(
            f"INSERT INTO collection_users (team_id, user_id) VALUES ('TEAM-1', '{member}');"
        )
    lines.append("-- NOTE: no collection_users row for U-B — deliberate exclusion.")
    for s in TEAM_1["shared_ciphers"]:
        lines.append(
            "INSERT INTO shared_ciphers (share_id, cipher_id, team_id, name, data) VALUES "
            f"('{s['share_id']}', '{s['cipher_id']}', '{s['team_id']}', "
            f"'{s['name']}', '{s['secret_placeholder']}');"
        )

    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(
        description="Emit the synthetic Locker seed-data fixture (JSON by default, or --sql)."
    )
    parser.add_argument(
        "--sql",
        action="store_true",
        help="Emit MySQL-flavored INSERT statements instead of the JSON fixture.",
    )
    args = parser.parse_args()

    if args.sql:
        emit_sql()
    else:
        emit_json()

    return 0


if __name__ == "__main__":
    sys.exit(main())
