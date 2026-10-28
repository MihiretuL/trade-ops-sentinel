"""Strict byte-counted FIX 4.2/4.4 parser and builder.

Pipe-delimited fixtures are explicitly test representations, not production wire.
For their protocol validation only, `|` is normalized to SOH before the checksum
is calculated; original source text and delimiter remain available on FixMessage.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .models import FixField, FixMessage

SOH = "\x01"
PIPE = "|"
_SUPPORTED_BEGIN_STRINGS = {"FIX.4.2", "FIX.4.4"}

# Institutional FIX 4.2/4.4 tag dictionary used by report renderers and UI decoders.
FIX_TAGS: dict[int, str] = {
    1: "Account", 6: "AvgPx", 7: "BeginSeqNo", 8: "BeginString", 9: "BodyLength",
    10: "CheckSum", 11: "ClOrdID", 12: "Commission", 13: "CommType", 14: "CumQty",
    15: "Currency", 16: "EndSeqNo", 17: "ExecID", 18: "ExecInst", 19: "ExecRefID",
    20: "ExecTransType", 21: "HandlInst", 22: "IDSource", 30: "LastMkt", 31: "LastPx",
    32: "LastQty", 34: "MsgSeqNum", 35: "MsgType", 36: "NewSeqNo", 37: "OrderID",
    38: "OrderQty", 39: "OrdStatus", 40: "OrdType", 41: "OrigClOrdID", 43: "PossDupFlag",
    44: "Price", 45: "RefSeqNum", 47: "Rule80A", 49: "SenderCompID", 50: "SenderSubID",
    52: "SendingTime", 54: "Side", 55: "Symbol", 56: "TargetCompID", 57: "TargetSubID",
    58: "Text", 59: "TimeInForce", 60: "TransactTime", 63: "SettlmntTyp", 64: "FutSettDate",
    75: "TradeDate", 97: "PossResend", 98: "EncryptMethod", 102: "CxlRejReason",
    103: "OrdRejReason", 108: "HeartBtInt", 112: "TestReqID", 123: "GapFillFlag",
    122: "OrigSendingTime", 128: "DeliverToCompID", 129: "DeliverToSubID", 141: "ResetSeqNumFlag",
    142: "SenderLocationID", 143: "TargetLocationID", 150: "ExecType", 151: "LeavesQty",
    167: "SecurityType", 192: "OrderQty2", 193: "FutSettDate2", 207: "SecurityExchange",
    210: "MaxShow", 211: "PegDifference", 336: "TradingSessionID", 369: "LastMsgSeqNumProcessed",
    371: "RefTagID", 372: "RefMsgType", 373: "SessionRejectReason", 378: "ExecRestatementReason",
    381: "GrossTradeAmt", 432: "ExpireDate", 434: "CxlRejResponseTo", 442: "MultiLegReportingType",
}


class FixError(ValueError):
    """Base class for FIX framing and field errors."""


class FixParseError(FixError):
    """FIX validation exception with machine-readable validation details."""

    def __init__(self, *errors: str):
        self.validation_errors = list(errors)
        self.is_structurally_valid = False
        super().__init__("; ".join(errors))


def _normalize_fields(
    tag_pairs: Mapping[int | str, object] | Iterable[FixField | tuple[int | str, object]],
) -> list[tuple[int, str]]:
    items = tag_pairs.items() if isinstance(tag_pairs, Mapping) else tag_pairs
    result: list[tuple[int, str]] = []
    seen: set[int] = set()
    for pair in items:
        if isinstance(pair, FixField):
            tag, value = pair.tag, pair.value
        else:
            try:
                tag, value = pair
            except (TypeError, ValueError) as exc:
                raise FixParseError(f"Expected a (tag, value) pair, got {pair!r}") from exc
        try:
            numeric_tag = int(tag)
        except (TypeError, ValueError) as exc:
            raise FixParseError(f"Invalid FIX tag {tag!r}") from exc
        if numeric_tag <= 0:
            raise FixParseError(f"FIX tag must be positive, got {numeric_tag}")
        if numeric_tag in seen:
            raise FixParseError(f"Duplicate FIX tag {numeric_tag}")
        seen.add(numeric_tag)
        text = str(value)
        if SOH in text or PIPE in text:
            raise FixParseError(f"FIX tag {numeric_tag} value contains a field delimiter")
        result.append((numeric_tag, text))
    return result


def build_fix_message(
    tag_pairs: Mapping[int | str, object] | Iterable[FixField | tuple[int | str, object]],
    *,
    begin_string: str = "FIX.4.4",
    delimiter: str = SOH,
) -> str:
    """Build FIX from unique `tag_pairs`, including exactly one `(35, msg_type)`.

    Tags 8, 9 and 10 are generated. MsgType is emitted first in the body,
    followed by the remaining input fields in their supplied order.
    """
    if begin_string not in _SUPPORTED_BEGIN_STRINGS:
        raise FixParseError(f"Unsupported BeginString {begin_string!r}")
    if delimiter not in (SOH, PIPE):
        raise FixParseError("Delimiter must be SOH or pipe")
    normalized = _normalize_fields(tag_pairs)
    if any(tag in (8, 9, 10) for tag, _ in normalized):
        raise FixParseError("Tags 8, 9 and 10 are generated framing fields")
    msg_types = [(tag, value) for tag, value in normalized if tag == 35]
    if len(msg_types) != 1:
        raise FixParseError("tag_pairs must include exactly one MsgType (35, msg_type)")
    ordered = [msg_types[0], *((tag, value) for tag, value in normalized if tag != 35)]
    delim = delimiter.encode("ascii")
    body = b"".join(f"{tag}={value}".encode("utf-8") + delim for tag, value in ordered)
    prefix = f"8={begin_string}".encode("ascii") + delim
    prefix += f"9={len(body)}".encode("ascii") + delim + body
    checksum_basis = prefix.replace(b"|", b"\x01") if delimiter == PIPE else prefix
    checksum = sum(checksum_basis) % 256
    return (prefix + f"10={checksum:03d}".encode("ascii") + delim).decode("utf-8")


def parse_fix_message(wire: str | bytes, *, validate: bool = True) -> FixMessage:
    """Parse one complete FIX message; invalid input raises structured FixParseError.

    Set `validate=False` to inspect a parseable message with structural errors;
    it returns them on `validation_errors` and marks `is_structurally_valid=False`.
    Unparseable byte/field syntax always raises FixParseError.
    """
    raw = wire.encode("utf-8") if isinstance(wire, str) else bytes(wire)
    if not raw:
        raise FixParseError("FIX message is empty")
    if raw.endswith(b"\x01"):
        delimiter_bytes, delimiter = b"\x01", SOH
    elif raw.endswith(b"|"):
        delimiter_bytes, delimiter = b"|", PIPE
    else:
        raise FixParseError("FIX message must end with its field delimiter")
    other_delimiter = b"|" if delimiter == SOH else b"\x01"
    if other_delimiter in raw:
        raise FixParseError("FIX message mixes SOH and pipe delimiters")
    try:
        raw_text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FixParseError("FIX message is not valid UTF-8") from exc

    tokens = raw.split(delimiter_bytes)[:-1]
    if not tokens:
        raise FixParseError("FIX message is empty")
    parsed: list[FixField] = []
    for index, token in enumerate(tokens, start=1):
        if b"=" not in token:
            raise FixParseError(f"Malformed field at position {index}: missing '='")
        tag_bytes, value_bytes = token.split(b"=", 1)
        try:
            tag_text = tag_bytes.decode("ascii")
            tag = int(tag_text)
            value = value_bytes.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise FixParseError(f"Malformed tag or value at position {index}") from exc
        if not tag_text.isdigit() or tag <= 0:
            raise FixParseError(f"Invalid FIX tag {tag_text!r}")
        parsed.append(FixField(tag=tag, value=value))

    errors: list[str] = []
    tags = [field.tag for field in parsed]
    if len(parsed) < 4:
        errors.append("Required structural fields 8, 9, 35 and 10 are not all present")
    for tag in (8, 9, 35, 10):
        if tag not in tags:
            errors.append(f"Missing required structural tag {tag}")
    for tag in sorted({value for value in tags if tags.count(value) > 1}):
        errors.append(f"Duplicate FIX tag {tag}")
    if parsed[0].tag != 8:
        errors.append("BeginString(8) must be first")
    if len(parsed) > 1 and parsed[1].tag != 9:
        errors.append("BodyLength(9) must be second")
    if len(parsed) > 2 and parsed[2].tag != 35:
        errors.append("MsgType(35) must be third")
    if parsed[-1].tag != 10:
        errors.append("CheckSum(10) must be last")

    values = {field.tag: field.value for field in parsed}
    begin_string = values.get(8, "")
    if begin_string not in _SUPPORTED_BEGIN_STRINGS:
        errors.append(f"Unsupported or invalid BeginString(8) {begin_string!r}")
    body_length_text = values.get(9, "")
    if not body_length_text.isdigit():
        errors.append("BodyLength(9) must be a non-negative integer")
    checksum_text = values.get(10, "")
    if len(checksum_text) != 3 or not checksum_text.isdigit():
        errors.append("CheckSum(10) must be exactly three zero-padded decimal digits")

    if 9 in tags and 10 in tags:
        checksum_token_index = tags.index(10)
        checksum_start = sum(len(token) + len(delimiter_bytes) for token in tokens[:checksum_token_index])
        body_start = len(tokens[0]) + len(delimiter_bytes) + len(tokens[1]) + len(delimiter_bytes)
        canonical = raw.replace(b"|", b"\x01") if delimiter == PIPE else raw
        # Delimiters are one byte in either representation, so offsets are unchanged.
        actual_body_length = checksum_start - body_start
        if body_length_text.isdigit() and int(body_length_text) != actual_body_length:
            errors.append(f"BodyLength(9) mismatch: declared {body_length_text}, actual {actual_body_length}")
        if len(checksum_text) == 3 and checksum_text.isdigit():
            checksum_prefix = canonical[:checksum_start]
            expected = sum(checksum_prefix) % 256
            if int(checksum_text) != expected:
                errors.append(f"CheckSum(10) mismatch: declared {checksum_text}, expected {expected:03d}")

    structural_errors = any(
        any(marker in error for marker in ("Missing required", "must be first", "must be second", "must be third", "must be last", "Duplicate FIX tag"))
        for error in errors
    )
    if errors and validate:
        raise FixParseError(*errors)
    return FixMessage(
        begin_string=begin_string,
        fields=tuple(field for field in parsed if field.tag not in (8, 9, 10)),
        raw_wire=raw_text,
        delimiter=delimiter,
        validation_errors=errors,
        is_structurally_valid=not structural_errors and not errors,
    )
