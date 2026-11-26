import math
import re
import urllib.parse
from collections import Counter
from urllib.parse import urlparse
import json
import os
import pandas as pd


def safe_text(value):
    """
    Convert a value safely to text.

    This function intentionally matches the helper
    used during CSIC model training.
    """

    if pd.isna(value):
        return ""

    return str(value)


def decode_text(value):
    """
    URL-decode text exactly as performed during training.
    """

    value = safe_text(value)

    try:
        return urllib.parse.unquote_plus(
            value,
            errors="replace"
        )

    except Exception:
        return value


def calculate_entropy(text):
    """
    Calculate Shannon entropy.

    This implementation matches the V2 training pipeline.
    """

    text = safe_text(text)

    if not text:
        return 0.0

    counts = Counter(text)

    length = len(text)

    entropy = 0.0

    for count in counts.values():

        probability = (
            count / length
        )

        entropy -= (
            probability
            *
            math.log2(probability)
        )

    return entropy


def extract_http_features_v2(row):
    """
    Extract the exact 29 HTTP features used by
    the deployed CSIC V2 model.

    Expected row fields:
        Method
        URL
        content
    """

    method = safe_text(
        row.get("Method", "")
    ).upper()

    raw_url = safe_text(
        row.get("URL", "")
    )

    content = safe_text(
        row.get("content", "")
    )

    clean_url = raw_url.split(
        " HTTP/"
    )[0]

    decoded_url = decode_text(
        clean_url
    )

    decoded_content = decode_text(
        content
    )

    try:

        parsed = urlparse(
            decoded_url
        )

        path = parsed.path or ""
        query = parsed.query or ""

    except Exception:

        path = decoded_url
        query = ""

    payload = (
        query
        + " "
        + decoded_content
    )

    combined = (
        path
        + " "
        + payload
    )

    total_length = max(
        len(combined),
        1
    )

    printable_count = sum(
        c.isprintable()
        for c in combined
    )

    alpha_count = sum(
        c.isalpha()
        for c in combined
    )

    digit_count = sum(
        c.isdigit()
        for c in combined
    )

    whitespace_count = sum(
        c.isspace()
        for c in combined
    )

    alphanumeric_count = sum(
        c.isalnum()
        for c in combined
    )

    special_count = (
        total_length
        -
        alphanumeric_count
        -
        whitespace_count
    )

    return {

        # HTTP method
        "method_get":
            int(method == "GET"),

        "method_post":
            int(method == "POST"),

        "method_put":
            int(method == "PUT"),

        "method_other":
            int(
                method not in
                ["GET", "POST", "PUT"]
            ),

        # Structural lengths
        "path_length":
            len(path),

        "query_length":
            len(query),

        "payload_length":
            len(payload),

        "content_length":
            len(decoded_content),

        "parameter_count":
            (
                payload.count("&")
                +
                (
                    1
                    if "=" in payload
                    else 0
                )
            ),

        "path_depth":
            path.count("/"),

        # Character ratios
        "digit_ratio":
            digit_count
            /
            total_length,

        "alpha_ratio":
            alpha_count
            /
            total_length,

        "special_ratio":
            special_count
            /
            total_length,

        "whitespace_ratio":
            whitespace_count
            /
            total_length,

        "printable_ratio":
            printable_count
            /
            total_length,

        # Structural character counts
        "quote_count":
            (
                combined.count("'")
                +
                combined.count('"')
            ),

        "angle_bracket_count":
            (
                combined.count("<")
                +
                combined.count(">")
            ),

        "parenthesis_count":
            (
                combined.count("(")
                +
                combined.count(")")
            ),

        "semicolon_count":
            combined.count(";"),

        "equals_count":
            combined.count("="),

        "ampersand_count":
            combined.count("&"),

        "slash_count":
            combined.count("/"),

        "backslash_count":
            combined.count("\\"),

        "percent_count":
            combined.count("%"),

        "plus_count":
            combined.count("+"),

        # Encoding
        "encoded_sequence_count":
            len(
                re.findall(
                    r"%[0-9a-fA-F]{2}",
                    raw_url + content
                )
            ),

        # Statistical complexity
        "request_entropy":
            calculate_entropy(
                combined
            ),

        "payload_entropy":
            calculate_entropy(
                payload
            ),

        "unique_char_ratio":
            (
                len(set(combined))
                /
                total_length
            )
    }