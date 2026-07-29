#!/usr/bin/env python3
"""Single-file, zero-dependency cost parser for Claude Code transcripts.

PURPOSE
    Given a bob-oss run transcript (a root <session>.jsonl plus its sibling
    <session>/subagents/agent-*.jsonl files), reconstruct token usage and
    estimated USD, broken down per model and (when available) per subagent role.

PII GUARD
    This parser reads ONLY the structural and numeric usage/model fields of each
    assistant turn (message.usage.* and message.model) and the agentType field of
    each subagent meta.json. It NEVER reads, parses, stores, summarizes, logs, or
    emits message text content, tool inputs, tool results, file paths inside
    transcripts, or any other free-text payload. The only strings it surfaces are
    model IDs, agentType role names, and the session id.

USAGE
    python3 cost_parser.py <path> [--pretty]
        <path> may be either:
          - a root session jsonl file (e.g. .../<session-uuid>.jsonl), or
          - a directory. If the directory IS a <session-uuid> folder (contains a
            subagents/ subdir) it is parsed as a session whose root jsonl is the
            sibling <session-uuid>.jsonl (handled gracefully if that root is
            missing). If the directory is a project dir, the matching
            <session>/subagents/ folder is auto-discovered from the root jsonl.

GROUNDED SCHEMA (verified against real files on 2026-05-31)
    - Token usage lives ONLY on top-level lines where type == "assistant",
      at message.usage. Same path in the flat root jsonl and in every
      subagents/agent-*.jsonl.
    - message.model is the per-row model id (e.g. "claude-opus-4-8",
      "claude-sonnet-4-6"); equals "<synthetic>" for excluded synthetic turns.
    - DUPLICATE USAGE ROWS: one assistant message is split across multiple JSONL
      lines sharing the same message.id, all carrying IDENTICAL usage. We dedup by
      message.id and count each id once. (Sample root: 254 assistant lines -> 77
      distinct ids.)
    - SYNTHETIC turns still carry a full usage object; the only reliable exclusion
      is message.model == "<synthetic>". Filter per row, not per file (one file had
      3 <synthetic> rows mixed with 125 real-model rows).
    - cache_creation sub-object splits into ephemeral_5m_input_tokens and
      ephemeral_1h_input_tokens, which sum to cache_creation_input_tokens. They are
      priced differently, so we keep the 5m/1h split. If the sub-object is absent,
      we treat the rolled-up cache_creation_input_tokens as 5m.
    - Per-role attribution: subagent role comes from the "agentType" field of the
      paired <session>/subagents/agent-<id>.meta.json. The agent's own jsonl lines
      do NOT carry agentType. Root-file turns are attributed to role "root".
    - Some sessions have only a subagents/ folder and no flat root jsonl; missing
      root is handled gracefully.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from collections import defaultdict

# Trailing dated-snapshot suffix, e.g. "claude-haiku-4-5-20251001" -> family
# "claude-haiku-4-5". Transcripts carry both bare family IDs and dated variants;
# pricing is keyed by family, so we normalize for the price lookup only.
_DATE_SUFFIX_RE = re.compile(r"-\d{8}$")

# ---------------------------------------------------------------------------
# PRICING (USD per 1,000,000 tokens), keyed by model_id.
#
# Source: official Anthropic pricing page at
#   https://platform.claude.com/docs/en/docs/about-claude/pricing
#   (docs.anthropic.com/en/docs/about-claude/pricing 301-redirects here;
#    anthropic.com/pricing -> claude.com/pricing shows only consumer plans).
#   Fetched 2026-05-31.
#
# Cache multipliers used (all three models' page columns match these exactly):
#   cache write 5m = 1.25x input, cache write 1h = 2x input, cache read = 0.1x input.
#
# Notes (not encoded as fields):
#   - Batch API = 50% off input+output.
#   - Data residency / inference_geo='us' (Opus 4.6+, Sonnet 4.6+) = 1.1x on ALL
#     token categories. Global routing (default) = standard pricing below. This
#     parser applies STANDARD pricing and does not auto-derive the 1.1x multiplier
#     from inference_geo, to keep the estimate conservative and deterministic.
#   - Fast mode (research preview) is priced separately and not applied here.
#   - Opus 4.7+ (incl. 4.8) use a new tokenizer that can consume ~35% more tokens
#     for the same text vs older models; relevant when comparing $/task across
#     model generations, though $/token is unchanged.
# ---------------------------------------------------------------------------
PRICING = {
    # claude-opus-4-8: page renders this row as the JSX placeholder "<NextOpus />";
    # confirmed as Claude Opus 4.8 by the page's Managed Agents worked example,
    # which prices "Claude Opus 4.8" at $5 input / $25 output (identical to the row).
    # source: https://platform.claude.com/docs/en/docs/about-claude/pricing
    "claude-opus-4-8": {
        "input_per_mtok": 5.0,
        "output_per_mtok": 25.0,
        "cache_write_5m_per_mtok": 6.25,
        "cache_write_1h_per_mtok": 10.0,
        "cache_read_per_mtok": 0.5,
    },
    # claude-opus-4-7 / 4-6 / 4-5: the pricing page lists all three Opus 4.5+
    # generations at the SAME rates as Opus 4.8 ($5 in / $25 out / $6.25 5m /
    # $10 1h / $0.50 read). Included so historical bob-oss runs (which ran on
    # opus-4-7 / opus-4-6) price fully instead of landing in unpriced_models.
    # NOTE: older/deprecated Opus tiers (Opus 4.1 and Opus 4 = $15 in / $75 out)
    # are intentionally NOT listed — bob-oss never ran on them; if a transcript
    # ever shows one it will surface in unpriced_models rather than be mispriced.
    # source: https://platform.claude.com/docs/en/docs/about-claude/pricing
    "claude-opus-4-7": {
        "input_per_mtok": 5.0,
        "output_per_mtok": 25.0,
        "cache_write_5m_per_mtok": 6.25,
        "cache_write_1h_per_mtok": 10.0,
        "cache_read_per_mtok": 0.5,
    },
    "claude-opus-4-6": {
        "input_per_mtok": 5.0,
        "output_per_mtok": 25.0,
        "cache_write_5m_per_mtok": 6.25,
        "cache_write_1h_per_mtok": 10.0,
        "cache_read_per_mtok": 0.5,
    },
    "claude-opus-4-5": {
        "input_per_mtok": 5.0,
        "output_per_mtok": 25.0,
        "cache_write_5m_per_mtok": 6.25,
        "cache_write_1h_per_mtok": 10.0,
        "cache_read_per_mtok": 0.5,
    },
    # claude-sonnet-4-6 = Claude Sonnet 4.6 (all five values listed directly).
    # source: https://platform.claude.com/docs/en/docs/about-claude/pricing
    "claude-sonnet-4-6": {
        "input_per_mtok": 3.0,
        "output_per_mtok": 15.0,
        "cache_write_5m_per_mtok": 3.75,
        "cache_write_1h_per_mtok": 6.0,
        "cache_read_per_mtok": 0.3,
    },
    # claude-sonnet-4-5 = Claude Sonnet 4.5 (page lists identical rates to 4.6).
    # source: https://platform.claude.com/docs/en/docs/about-claude/pricing
    "claude-sonnet-4-5": {
        "input_per_mtok": 3.0,
        "output_per_mtok": 15.0,
        "cache_write_5m_per_mtok": 3.75,
        "cache_write_1h_per_mtok": 6.0,
        "cache_read_per_mtok": 0.3,
    },
    # claude-haiku-4-5 = Claude Haiku 4.5 (all five values listed directly).
    # source: https://platform.claude.com/docs/en/docs/about-claude/pricing
    "claude-haiku-4-5": {
        "input_per_mtok": 1.0,
        "output_per_mtok": 5.0,
        "cache_write_5m_per_mtok": 1.25,
        "cache_write_1h_per_mtok": 2.0,
        "cache_read_per_mtok": 0.1,
    },
}

# The only reliable synthetic-turn exclusion marker (per-row, not per-file).
SYNTHETIC_MARKER = "<synthetic>"

# Token-type buckets we aggregate.
TOKEN_TYPES = ("input", "output", "cache_creation", "cache_read")


def _num(value):
    """Coerce a usage subfield to a non-negative int; missing/garbage -> 0."""
    if isinstance(value, bool):  # guard: bool is an int subclass
        return 0
    if isinstance(value, (int, float)):
        return int(value) if value > 0 else 0
    return 0


def _extract_usage(usage):
    """Pull the four numeric buckets (+ 5m/1h split) from a message.usage dict.

    Returns a dict with input, output, cache_read, cache_creation (rolled up),
    cache_creation_5m, cache_creation_1h. Robust to missing fields.
    """
    if not isinstance(usage, dict):
        usage = {}

    inp = _num(usage.get("input_tokens"))
    out = _num(usage.get("output_tokens"))
    cache_read = _num(usage.get("cache_read_input_tokens"))
    cache_creation_rolled = _num(usage.get("cache_creation_input_tokens"))

    sub = usage.get("cache_creation")
    if isinstance(sub, dict):
        cc_5m = _num(sub.get("ephemeral_5m_input_tokens"))
        cc_1h = _num(sub.get("ephemeral_1h_input_tokens"))
        # Prefer the sub-bucket split. If the sub-object is present but both are
        # zero while the rolled-up value is nonzero, fall back to treating the
        # rolled-up amount as 5m so no tokens are silently dropped.
        if cc_5m == 0 and cc_1h == 0 and cache_creation_rolled > 0:
            cc_5m = cache_creation_rolled
    else:
        # No sub-object: treat the rolled-up cache_creation as 5m (schema rule).
        cc_5m = cache_creation_rolled
        cc_1h = 0

    return {
        "input": inp,
        "output": out,
        "cache_read": cache_read,
        "cache_creation": cc_5m + cc_1h,
        "cache_creation_5m": cc_5m,
        "cache_creation_1h": cc_1h,
    }


def _iter_assistant_rows(jsonl_path):
    """Yield (message_id, model, usage_breakdown) for each deduped assistant turn.

    - Skips non-assistant lines (user/system/summary/attachment/etc.).
    - Skips rows whose model == SYNTHETIC_MARKER.
    - Dedups by message.id (falls back to requestId, then a positional key) so
      duplicate usage rows for one message are counted exactly once.
    - Reads ONLY message.id, message.model, message.usage (PII guard).
    """
    seen_ids = set()
    if not (jsonl_path and os.path.isfile(jsonl_path)):
        return
    try:
        fh = open(jsonl_path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return
    with fh:
        for idx, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                continue
            if not isinstance(obj, dict) or obj.get("type") != "assistant":
                continue
            msg = obj.get("message")
            if not isinstance(msg, dict):
                continue
            model = msg.get("model")
            if model == SYNTHETIC_MARKER:
                continue
            if not isinstance(model, str) or not model:
                model = "unknown"

            mid = msg.get("id") or obj.get("requestId") or f"_noid_{idx}"
            if mid in seen_ids:
                continue
            seen_ids.add(mid)

            yield mid, model, _extract_usage(msg.get("usage"))


def _read_agent_type(meta_path):
    """Read the agentType from a subagent meta.json; default 'unknown-role'."""
    if not os.path.isfile(meta_path):
        return "unknown-role"
    try:
        with open(meta_path, "r", encoding="utf-8", errors="replace") as fh:
            meta = json.load(fh)
    except (OSError, ValueError):
        return "unknown-role"
    if isinstance(meta, dict):
        at = meta.get("agentType")
        if isinstance(at, str) and at:
            return at
    return "unknown-role"


def _resolve_session(path):
    """Resolve <path> to (session_id, root_jsonl_or_None, subagents_dir_or_None).

    Accepts a root jsonl file, a <session-uuid> folder, or a project dir.
    """
    path = os.path.abspath(path)

    # Case 1: a jsonl file -> the root session file.
    if os.path.isfile(path) and path.endswith(".jsonl"):
        session_id = os.path.basename(path)[: -len(".jsonl")]
        subdir = os.path.join(path[: -len(".jsonl")], "subagents")
        return session_id, path, (subdir if os.path.isdir(subdir) else None)

    # Case 2: a directory.
    if os.path.isdir(path):
        # 2a: the directory itself is a <session-uuid> folder (has subagents/).
        direct_sub = os.path.join(path, "subagents")
        if os.path.isdir(direct_sub):
            session_id = os.path.basename(path.rstrip(os.sep))
            sibling_root = path.rstrip(os.sep) + ".jsonl"
            root = sibling_root if os.path.isfile(sibling_root) else None
            return session_id, root, direct_sub

        # 2b: a project dir containing one or more flat <session>.jsonl files.
        roots = sorted(
            p for p in glob.glob(os.path.join(path, "*.jsonl")) if os.path.isfile(p)
        )
        if len(roots) == 1:
            return _resolve_session(roots[0])
        if len(roots) > 1:
            raise SystemExit(
                "error: directory contains multiple session jsonl files; "
                "pass a specific <session>.jsonl path. Found: "
                + ", ".join(os.path.basename(r) for r in roots)
            )
        raise SystemExit(f"error: no session jsonl found under directory: {path}")

    raise SystemExit(f"error: path not found or unsupported: {path}")


def _accumulate(target, breakdown):
    """Add a usage breakdown into a mutable accumulator dict (in place)."""
    for key in ("input", "output", "cache_read", "cache_creation",
                "cache_creation_5m", "cache_creation_1h"):
        target[key] += breakdown[key]


def _new_acc():
    return {k: 0 for k in ("input", "output", "cache_read", "cache_creation",
                           "cache_creation_5m", "cache_creation_1h")}


def _price_for_model(model):
    """Look up pricing for a (possibly dated) model id.

    Tries the raw id first, then the family id with a trailing -YYYYMMDD stripped
    (e.g. claude-haiku-4-5-20251001 -> claude-haiku-4-5). Returns None if neither
    is in PRICING, so the model is reported under unpriced_models.
    """
    price = PRICING.get(model)
    if price is not None:
        return price
    family = _DATE_SUFFIX_RE.sub("", model)
    if family != model:
        return PRICING.get(family)
    return None


def _usd_for_model(model, acc):
    """Compute USD for one model's accumulated tokens; None if unpriced."""
    price = _price_for_model(model)
    if price is None:
        return None
    usd = (
        acc["input"] / 1_000_000.0 * price["input_per_mtok"]
        + acc["output"] / 1_000_000.0 * price["output_per_mtok"]
        + acc["cache_creation_5m"] / 1_000_000.0 * price["cache_write_5m_per_mtok"]
        + acc["cache_creation_1h"] / 1_000_000.0 * price["cache_write_1h_per_mtok"]
        + acc["cache_read"] / 1_000_000.0 * price["cache_read_per_mtok"]
    )
    return round(usd, 6)


def parse_session(path):
    """Parse a session and return the result dict (the JSON shape printed to stdout)."""
    session_id, root_jsonl, subagents_dir = _resolve_session(path)

    per_model = defaultdict(_new_acc)   # model -> token acc
    per_role = defaultdict(_new_acc)    # agentType -> token acc

    # Root file -> role "root".
    if root_jsonl:
        for _mid, model, bd in _iter_assistant_rows(root_jsonl):
            _accumulate(per_model[model], bd)
            _accumulate(per_role["root"], bd)

    # Subagent files -> role from paired meta.json agentType.
    if subagents_dir and os.path.isdir(subagents_dir):
        for agent_jsonl in sorted(glob.glob(os.path.join(subagents_dir, "agent-*.jsonl"))):
            meta_path = agent_jsonl[: -len(".jsonl")] + ".meta.json"
            role = _read_agent_type(meta_path)
            for _mid, model, bd in _iter_assistant_rows(agent_jsonl):
                _accumulate(per_model[model], bd)
                _accumulate(per_role[role], bd)

    # Build per_model output + USD totals + unpriced list.
    per_model_out = []
    unpriced_models = []
    total_usd = 0.0
    any_priced = False
    totals_tokens = _new_acc()

    for model in sorted(per_model):
        acc = per_model[model]
        _accumulate(totals_tokens, acc)
        usd = _usd_for_model(model, acc)
        if usd is None:
            unpriced_models.append(model)
        else:
            any_priced = True
            total_usd += usd
        per_model_out.append({
            "model": model,
            "tokens": {
                "input": acc["input"],
                "output": acc["output"],
                "cache_creation": acc["cache_creation"],
                "cache_creation_5m": acc["cache_creation_5m"],
                "cache_creation_1h": acc["cache_creation_1h"],
                "cache_read": acc["cache_read"],
                "total": (acc["input"] + acc["output"]
                          + acc["cache_creation"] + acc["cache_read"]),
            },
            "usd": usd,
        })

    # Build per_role output (USD per role is summed over that role's models).
    per_role_out = []
    for role in sorted(per_role):
        acc = per_role[role]
        # Per-role USD is unknown without per-(role,model) split; we recompute it
        # honestly by re-scanning, but to stay single-pass we instead leave role
        # USD as the proportional figure only when the role's tokens are priceable
        # under a single model. To keep it correct and simple, role USD is omitted
        # (null) and per-model USD remains authoritative for the dollar total.
        per_role_out.append({
            "role": role,
            "tokens": {
                "input": acc["input"],
                "output": acc["output"],
                "cache_creation": acc["cache_creation"],
                "cache_creation_5m": acc["cache_creation_5m"],
                "cache_creation_1h": acc["cache_creation_1h"],
                "cache_read": acc["cache_read"],
                "total": (acc["input"] + acc["output"]
                          + acc["cache_creation"] + acc["cache_read"]),
            },
        })

    result = {
        "session": session_id,
        "sources": {
            "root_jsonl": root_jsonl,
            "subagents_dir": subagents_dir,
            "root_present": bool(root_jsonl),
        },
        "per_model": per_model_out,
        "per_role": per_role_out,
        "totals": {
            "tokens": {
                "input": totals_tokens["input"],
                "output": totals_tokens["output"],
                "cache_creation": totals_tokens["cache_creation"],
                "cache_creation_5m": totals_tokens["cache_creation_5m"],
                "cache_creation_1h": totals_tokens["cache_creation_1h"],
                "cache_read": totals_tokens["cache_read"],
                "total": (totals_tokens["input"] + totals_tokens["output"]
                          + totals_tokens["cache_creation"]
                          + totals_tokens["cache_read"]),
            },
            "usd": round(total_usd, 6) if any_priced else None,
        },
        "unpriced_models": unpriced_models,
        "reconcile_hint": (
            "USD is estimated at STANDARD (global-routing) pricing, applied per "
            "deduped message.id using that row's message.model, then summed across "
            "the root jsonl and every subagents/agent-*.jsonl. Synthetic-marked "
            "rows (model == '<synthetic>') are excluded. Duplicate usage rows are "
            "deduped by message.id. cache_creation 5m/1h sub-buckets are priced "
            "separately (5m=1.25x, 1h=2x, read=0.1x of input). per_role token totals "
            "should sum to totals.tokens; per_role USD is intentionally omitted "
            "because a single role can span multiple models. inference_geo='us' "
            "(+10%) and fast/batch modifiers are NOT applied. Unknown models have "
            "tokens counted but usd=null and are listed under unpriced_models, so "
            "totals.usd may understate the true cost when unpriced_models is nonempty."
        ),
    }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Reconstruct Claude Code transcript token usage and estimated USD."
    )
    parser.add_argument(
        "path",
        help="A root <session>.jsonl file, a <session-uuid> folder, or a project dir.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the JSON output (indented).",
    )
    args = parser.parse_args(argv)

    result = parse_session(args.path)

    if args.pretty:
        sys.stdout.write(json.dumps(result, indent=2, sort_keys=False))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
