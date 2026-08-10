"""Pre-parse structural limits for untrusted JSON text."""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Tuple


DEFAULT_MAX_JSON_DEPTH = 64
DEFAULT_MAX_JSON_NODES = 65536
MAX_JSON_NUMBER_CHARACTERS = 256


def validate_json_text(
    text: str,
    *,
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
    max_nodes: int = DEFAULT_MAX_JSON_NODES,
) -> None:
    """Reject JSON text whose structure can amplify excessively during parsing.

    The scan does not validate JSON grammar. It bounds nesting and an upper
    approximation of containers, members, and values while ignoring delimiter
    characters inside quoted strings. ``json.loads`` remains the parser.
    """

    if not isinstance(text, str):
        raise ValueError("JSON input must be text")
    if max_depth <= 0 or max_nodes <= 0:
        raise ValueError("JSON structure limits must be positive")

    depth = 0
    nodes = 1
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            nodes += 1
            if depth > max_depth:
                raise ValueError("JSON exceeds the %d-level depth limit" % max_depth)
        elif character in "]}":
            if depth:
                depth -= 1
        elif character in ",:":
            nodes += 1
        if nodes > max_nodes:
            raise ValueError("JSON exceeds the %d-node structure limit" % max_nodes)


def strict_json_loads(text: str) -> Any:
    """Parse JSON while rejecting duplicate names and non-finite numbers.

    Call :func:`validate_json_text` first when the text is untrusted so depth
    and structural work are bounded before Python allocates the decoded tree.
    """

    def reject_constant(value: str) -> Any:
        raise ValueError("JSON contains non-finite number %s" % value)

    def bounded_int(value: str) -> int:
        if len(value) > MAX_JSON_NUMBER_CHARACTERS:
            raise ValueError("JSON integer token exceeds the numeric length limit")
        return int(value)

    def bounded_float(value: str) -> float:
        if len(value) > MAX_JSON_NUMBER_CHARACTERS:
            raise ValueError("JSON float token exceeds the numeric length limit")
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("JSON float is not finite")
        return parsed

    def unique_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("JSON object contains duplicate name %r" % key)
            result[key] = value
        return result

    return json.loads(
        text,
        object_pairs_hook=unique_object,
        parse_int=bounded_int,
        parse_float=bounded_float,
        parse_constant=reject_constant,
    )
