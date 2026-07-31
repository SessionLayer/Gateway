#!/usr/bin/env python3
"""Every `span_name="..."` selector in deploy/observability must name a span the
code actually emits.

The shipped alert rules ARE a check, and a PromQL selector that matches nothing
evaluates to no alert -- indistinguishable, on a dashboard or in alertmanager,
from a healthy fleet. Two rules shipped selecting `host_verify` and
`node.connect` while the code emits `gateway.host_verify` and
`gateway.node.connect`, so the host-identity alert an operator relies on to see
an unenrolled host key could never fire.

The Gateway inventory is derived from source, never from a list kept in step by
hand. Agent span names cannot be: they live in the SessionLayer/Agent
repository, which is not checked out here, so they are declared below and that
is a real limit of this check rather than a hole hidden in it.

Usage: check_span_selectors.py <repo-root>
Exit 0 all selectors resolve, 1 otherwise.
"""
import pathlib
import re
import sys

# Cross-repo: emitted by SessionLayer/Agent (src/gateway/client.rs). Not
# derivable here. Adding a name to this list without the Agent source in front
# of you reintroduces exactly the defect this script exists to catch.
AGENT_SPANS = {"agent.dial_back", "agent.splice"}

SPAN_MACRO = re.compile(r"\b\w*span!\s*\(\s*(?:parent\s*:\s*[^,]+,\s*)?\"([^\"]+)\"")
INSTRUMENT_ATTR = re.compile(r"#\[[^\]]*?\binstrument\s*\([^)]*?name\s*=\s*\"([^\"]+)\"")
SELECTOR_BLOCK = re.compile(r"\{[^{}]*\bspan_name\s*=\s*\"[^\"]+\"[^{}]*\}")
LABEL = re.compile(r"\b(service_name|span_name)\s*=\s*\"([^\"]+)\"")


def emitted_spans(root):
    names = set()
    for rs in sorted((root / "gateway-core" / "src").rglob("*.rs")):
        text = rs.read_text(encoding="utf-8")
        names |= set(SPAN_MACRO.findall(text))
        names |= set(INSTRUMENT_ATTR.findall(text))
    return names


def main():
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    gateway_spans = emitted_spans(root)
    if not gateway_spans:
        print("FAIL: no spans found in gateway-core/src -- the extractor matched "
              "nothing, so this check would pass vacuously", file=sys.stderr)
        return 1

    yamls = sorted((root / "deploy" / "observability").glob("*.yaml"))
    if not yamls:
        print("FAIL: no deploy/observability/*.yaml to check", file=sys.stderr)
        return 1

    checked, bad = 0, []
    for path in yamls:
        for block in SELECTOR_BLOCK.findall(path.read_text(encoding="utf-8")):
            labels = dict(LABEL.findall(block))
            span, service = labels.get("span_name"), labels.get("service_name")
            checked += 1
            if service == "sessionlayer-gateway":
                allowed, source = gateway_spans, "gateway-core/src"
            elif service == "sessionlayer-agent":
                allowed, source = AGENT_SPANS, "the declared Agent set"
            else:
                bad.append(f"{path.name}: span_name={span!r} has no known "
                           f"service_name (got {service!r}), so it cannot be checked")
                continue
            if span not in allowed:
                bad.append(f"{path.name}: span_name={span!r} is emitted nowhere in "
                           f"{source}; this selector matches no series. "
                           f"Known: {', '.join(sorted(allowed))}")

    if not checked:
        print("FAIL: no span_name selectors found -- the selector pattern matched "
              "nothing, so this check would pass vacuously", file=sys.stderr)
        return 1
    if bad:
        print("\n".join(f"FAIL: {b}" for b in bad), file=sys.stderr)
        return 1
    print(f"OK: {checked} span_name selectors all resolve "
          f"({len(gateway_spans)} spans emitted by gateway-core)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
