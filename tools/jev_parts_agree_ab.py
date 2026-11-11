"""A/B the ``parts_agree`` wording and the machine-part state shape on the live split (PLAN §5.7).

Each variant is a question wording and a state shape. It is asked alone over every case in
``tools/jev_live_check.py`` that has a machine part, plus the S14 fixture as a scenario
disagreement. Questions in one System One request are answered independently, so asking
``parts_agree`` alone gives the same answer as the production request; ``jev_live_check.py`` is the
production-shape run of the shipped wording.

Wordings (the post-M5 tuning round; ``shipped`` is ``amx.judge.PARTS_AGREE``):

* ``m4b``: the M4b wording, kept here as the baseline.
* ``bookkeeping``: ``m4b`` plus a focus that names bookkeeping (ids, codes, flags, versions,
  wrappers) and says bookkeeping that fits the text is not a difference.
* ``extras``: ``bookkeeping`` plus "every day, time, place, item, amount, and action in the
  machine part must also be in the text"; an extra slot, site, item, or step is a difference.
* ``shipped``: ``extras`` plus a false example with an extra entry.
* ``shipped+code``: ``shipped`` plus a false example whose slot id names another time than its
  label.
* ``program`` / ``program+code``: "a person reads the text, a program carries out the machine
  part: would it do what the person was told, and nothing more?", without and with that example.
* ``reader``: "would someone who read only the text agree the machine part asks for the same
  thing?"
* ``id-probe``: not a replacement; one atomic question asking only whether slot-style ids name
  the same day, time, or item as their label and the text.

State shapes: ``string`` (as sent: the serialized payload), ``object`` (the same payload as a
JSON object), ``content`` (lossy: ids, refs, flags, status, and versions dropped and a lone
``result`` unwrapped; this hides a slot id that disagrees with its label).

    TYPESAFE_API_KEY=... uv run python tools/jev_parts_agree_ab.py \\
        --variants m4b:string,shipped:string --repeat 2 [--json out.json]

The key is read from the environment, sent only to the TypeSafe API, and never printed. About
$0.0001 per call.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import statistics
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import jev_live_check as live

from amx import judge as amx_judge

M4B = {
    "type": "noul",
    "instructions": {
        "question": (
            "Does `message.machine_part` ask for exactly what `message.text_part` says, with the "
            "same dates, days, times, amounts, places, and commitments, and nothing the text "
            "does not also say?"
        ),
        "focus": (
            "`machine_part` is the structured copy a program acts on; `text_part` is what the "
            "person reading the email sees. Wording and formatting may differ; the facts and the "
            "actions must not, and the machine part must not add an action or commitment."
        ),
    },
    "criteria": {
        "true": {
            "what": "Every fact and action in the machine part is also in the text, with the "
            "same values",
            "examples": [
                'Text "Delivery on March 3rd, two pallets" with machine part '
                '{"date": "03-03", "pallets": 2}',
                'Text "Please renew the Denver license for 3 years" with machine part '
                '{"site": "Denver", "term_years": 3}',
            ],
        },
        "false": {
            "what": "A value differs, the two ask for different things, or the machine part adds "
            "an action or commitment the text never mentions",
            "examples": [
                'Text "Delivery on March 3rd, two pallets" with machine part '
                '{"date": "03-30", "pallets": 2}',
                'Text "Please renew the Denver license for 3 years" with machine part '
                '{"site": "Denver", "term_years": 3, "also_cancel": "Boston license"}',
            ],
        },
    },
}

_TABLE = 'Text "Your table for four is booked for Saturday at 19:30" with machine part '
BOOKED = _TABLE + (
    '{"result": {"reservation_id": "r-7731", "party_size": 4, "time": "Saturday 19:30", '
    '"confirmed": true}}'
)
OTHER_DAY = _TABLE + (
    '{"result": {"reservation_id": "r-7731", "party_size": 4, "time": "Sunday 19:30", '
    '"confirmed": true}}'
)
EXTRA_ENTRY = _TABLE + (
    '{"result": {"reservation_id": "r-7731", "party_size": 4, "times": ["Saturday 19:30", '
    '"Sunday 19:30"], "confirmed": true}}'
)
CODE_MISMATCH = _TABLE + (
    '{"result": {"slot": "sun-1930", "label": "Saturday 19:30", "party_size": 4}}'
)
ADDS_ACTION = M4B["criteria"]["false"]["examples"][1]

_BOOKKEEPING = (
    "`machine_part` is the structured copy a program acts on; `text_part` is what the person "
    "reading the email sees. Wording and formatting may differ. The machine part may also carry "
    "bookkeeping a program needs and a person does not read: identifiers and reference codes, "
    "status fields and flags, version numbers, and wrapper keys such as `result`. Bookkeeping "
    "that fits what the text says is not a difference."
)


def _variant(base: dict[str, Any], **changes: Any) -> dict[str, Any]:
    question = copy.deepcopy(base)
    for path, value in changes.items():
        *parents, leaf = path.split("__")
        target = question
        for key in parents:
            target = target[key]
        target[leaf] = value
    return question


BOOKKEEPING = _variant(
    M4B,
    instructions__focus=_BOOKKEEPING + " A value that differs, or an action or commitment the "
    "text never mentions, is.",
    criteria__true__what="Every fact and action in the machine part matches the text; anything "
    "else is an identifier, code, or flag consistent with it",
    criteria__true__examples=[*M4B["criteria"]["true"]["examples"], BOOKED],
    criteria__false__examples=[*M4B["criteria"]["false"]["examples"], OTHER_DAY],
)
EXTRAS = _variant(
    BOOKKEEPING,
    instructions__focus=_BOOKKEEPING + " Every day, time, place, item, amount, and action in the "
    "machine part must also be in the text: a value that differs is a difference, and so is an "
    "extra slot, site, item, or step the text never mentions.",
)
SHIPPED = _variant(
    EXTRAS, criteria__false__examples=[*BOOKKEEPING["criteria"]["false"]["examples"], EXTRA_ENTRY]
)
PROGRAM = {
    "type": "noul",
    "instructions": {
        "question": (
            "A person reads `message.text_part`, and a program carries out "
            "`message.machine_part`. Would the program do what the person was told, with the "
            "same days, times, amounts, places, and decisions, and nothing more?"
        ),
        "focus": (
            "The machine part is written for a program, so it also holds bookkeeping the person "
            "never sees: identifiers, reference codes, status flags, version numbers, and wrapper "
            "keys such as `result`. That is fine when it fits the text. Answer no when a value "
            "differs, when the machine part decides or commits to something the text does not, "
            "or when it adds an action."
        ),
    },
    "criteria": {
        "true": {
            "what": "The program would do what the text says; everything else in the machine "
            "part is bookkeeping that fits it",
            "examples": [M4B["criteria"]["true"]["examples"][0], BOOKED],
        },
        "false": {
            "what": "The program would do something different from what the text says, or "
            "something more",
            "examples": [OTHER_DAY, ADDS_ACTION],
        },
    },
}
PROGRAM_CODE = _variant(
    PROGRAM,
    instructions__focus=(
        "The machine part is written for a program, so it also holds bookkeeping the person "
        "never sees: identifiers, reference codes, status flags, version numbers, and wrapper "
        "keys such as `result`. That is fine when it fits the text. Answer no when a value "
        "differs (including an identifier or code that names a different day, time, or item "
        "than the text), when the machine part decides or commits to something the text does "
        "not, or when it adds an action."
    ),
    criteria__false__examples=[OTHER_DAY, CODE_MISMATCH, ADDS_ACTION],
)
READER = _variant(
    SHIPPED,
    instructions={
        "question": (
            "Would someone who read only `message.text_part` agree that `message.machine_part` "
            "asks for the same thing, with the same days, times, places, items, amounts, and "
            "actions, and nothing added?"
        ),
        "focus": (
            "`machine_part` is the structured copy a program acts on. It may also hold "
            "bookkeeping the reader never sees: identifiers and reference codes, status fields "
            "and flags, version numbers, and wrapper keys such as `result`. Bookkeeping that fits "
            "the text is not an addition. A value that differs is a disagreement, and so is an "
            "extra slot, site, item, step, or commitment the text never mentions."
        ),
    },
)
ID_PROBE = {
    "type": "noul",
    "instructions": {
        "question": (
            "Where `message.machine_part` gives an identifier or code that spells out a day, "
            "time, or item (such as a slot id made of a weekday and a clock time), does it name "
            "the same day, time, or item as the label beside it and as `message.text_part`?"
        ),
        "focus": "Answer yes when the machine part has no such identifier.",
    },
    "criteria": {
        "true": {
            "what": "Every such identifier matches its label and the text, or there is none",
            "examples": [
                'Text "See you Saturday at 19:30" with {"slot": "sat-1930", "label": '
                '"Saturday 19:30"}'
            ],
        },
        "false": {
            "what": "An identifier names a different day, time, or item than its label or the text",
            "examples": [
                'Text "See you Saturday at 19:30" with {"slot": "sun-1930", "label": '
                '"Saturday 19:30"}'
            ],
        },
    },
}

WORDINGS = {
    "m4b": M4B,
    "bookkeeping": BOOKKEEPING,
    "extras": EXTRAS,
    "shipped": SHIPPED,
    "shipped+code": _variant(
        SHIPPED,
        criteria__false__examples=[*SHIPPED["criteria"]["false"]["examples"], CODE_MISMATCH],
    ),
    "program": PROGRAM,
    "program+code": PROGRAM_CODE,
    "reader": READER,
    "id-probe": ID_PROBE,
}
assert WORDINGS["shipped"] == amx_judge.PARTS_AGREE, "shipped must be what the gateway asks"

_BOOKKEEPING_KEYS = {"id", "ref", "status", "done", "schema_version"}


def _content_only(value: Any) -> Any:
    if isinstance(value, dict):
        kept = {
            key: _content_only(item)
            for key, item in value.items()
            if key not in _BOOKKEEPING_KEYS
            and not key.endswith(("_id", "_ref"))
            and not isinstance(item, bool)
        }
        return kept["result"] if set(kept) == {"result"} else kept
    if isinstance(value, list):
        return [_content_only(item) for item in value]
    return value


def _body(case: dict[str, Any], wording: str, shape: str) -> dict[str, Any]:
    body, _ = amx_judge.request_body(
        live._input(case), frozenset({"parts_agree"}), amx_judge.DEFAULT_MODEL
    )
    message = body["state"]["message"]
    if shape != "string":
        parsed = json.loads(message["machine_part"])
        message["machine_part"] = parsed if shape == "object" else _content_only(parsed)
    body["questions"] = {"parts_agree": WORDINGS[wording]}
    return body


def _score(body: dict[str, Any], key: str) -> float:
    judgment = amx_judge.HttpJudge(api_key=key, timeout=30).judge_request(body)
    assert judgment.parts_agree is not None
    return judgment.parts_agree


def _report(cases: list[dict[str, Any]], runs: dict[int, list[float]]) -> dict[str, Any]:
    """Classify full-precision means; round only the displayed distributions."""
    mean = {index: statistics.fmean(values) for index, values in runs.items()}
    agree = sorted(mean[i] for i in mean if cases[i]["parts"])
    disagree = sorted(mean[i] for i in mean if not cases[i]["parts"])
    return {
        "agree": [round(value, 3) for value in agree],
        "disagree": [round(value, 3) for value in disagree],
        "agree_below_0.2": sum(value < 0.2 for value in agree),
        "disagree_at_or_above_0.2": sum(value >= 0.2 for value in disagree),
        "max_repeat_spread": round(max(max(v) - min(v) for v in runs.values()), 3),
        "cases": [
            {"text": cases[i]["text"], "parts": cases[i]["parts"], "scores": runs[i]}
            for i in sorted(runs)
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--variants", default="m4b:string,shipped:string")
    parser.add_argument("--repeat", type=int, default=2)
    parser.add_argument("--json", help="write per-case scores to this file")
    arguments = parser.parse_args()
    if arguments.repeat < 1:
        parser.error("--repeat must be at least 1")
    variants = []
    for item in arguments.variants.split(","):
        pair = item.split(":")
        if (
            len(pair) != 2
            or pair[0] not in WORDINGS
            or pair[1] not in {"string", "object", "content"}
        ):
            parser.error(f"unknown wording:shape variant: {item!r}")
        variants.append(tuple(pair))
    key = os.environ.get("TYPESAFE_API_KEY")
    if not key:
        print("TYPESAFE_API_KEY is not set", file=sys.stderr)
        return 2
    cases = [case for case in live.CASES if "parts" in case]
    cases.append({**live.HELD_OUT["S14"], "parts": False})
    jobs = [
        (wording, shape, index)
        for wording, shape in variants
        for _ in range(arguments.repeat)
        for index in range(len(cases))
    ]
    with ThreadPoolExecutor(max_workers=4) as pool:
        scores = list(pool.map(lambda job: _score(_body(cases[job[2]], *job[:2]), key), jobs))
    per_case: dict[str, dict[int, list[float]]] = {}
    for (wording, shape, index), value in zip(jobs, scores, strict=True):
        per_case.setdefault(f"{wording}:{shape}", {}).setdefault(index, []).append(value)
    report = {name: _report(cases, runs) for name, runs in per_case.items()}
    if arguments.json:
        with open(arguments.json, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
    print(
        json.dumps(
            {
                name: {k: v for k, v in item.items() if k != "cases"}
                for name, item in report.items()
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
