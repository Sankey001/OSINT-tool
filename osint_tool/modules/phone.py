"""Phone number analysis. Uses Google's libphonenumber (``phonenumbers``)
when installed, with a small built-in calling-code table as a fallback."""

from . import ModuleError, module

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone as pn_timezone
except ImportError:  # optional dependency
    phonenumbers = None

CALLING_CODES = {
    "1": "United States / Canada", "7": "Russia / Kazakhstan", "20": "Egypt", "27": "South Africa",
    "30": "Greece", "31": "Netherlands", "32": "Belgium", "33": "France", "34": "Spain",
    "36": "Hungary", "39": "Italy", "40": "Romania", "41": "Switzerland", "43": "Austria",
    "44": "United Kingdom", "45": "Denmark", "46": "Sweden", "47": "Norway", "48": "Poland",
    "49": "Germany", "51": "Peru", "52": "Mexico", "54": "Argentina", "55": "Brazil",
    "56": "Chile", "57": "Colombia", "60": "Malaysia", "61": "Australia", "62": "Indonesia",
    "63": "Philippines", "64": "New Zealand", "65": "Singapore", "66": "Thailand", "81": "Japan",
    "82": "South Korea", "84": "Vietnam", "86": "China", "90": "Turkey", "91": "India",
    "92": "Pakistan", "93": "Afghanistan", "94": "Sri Lanka", "95": "Myanmar", "98": "Iran",
    "212": "Morocco", "234": "Nigeria", "254": "Kenya", "351": "Portugal", "353": "Ireland",
    "358": "Finland", "380": "Ukraine", "880": "Bangladesh", "966": "Saudi Arabia",
    "971": "United Arab Emirates", "972": "Israel", "977": "Nepal",
}

LINE_TYPES = {
    0: "Fixed line", 1: "Mobile", 2: "Fixed line or mobile", 3: "Toll free", 4: "Premium rate",
    5: "Shared cost", 6: "VoIP", 7: "Personal number", 8: "Pager", 9: "UAN", 10: "Voicemail",
    99: "Unknown",
}


def fallback(number):
    digits = number.lstrip("+")
    if not number.startswith("+"):
        return {"e164": None, "valid": None, "country": None,
                "note": "Add the international prefix (e.g. +44...) for a full analysis"}
    for size in (3, 2, 1):
        if digits[:size] in CALLING_CODES:
            return {"e164": number, "calling_code": f"+{digits[:size]}",
                    "country": CALLING_CODES[digits[:size]], "valid": None,
                    "note": "Install 'phonenumbers' for carrier, line type and validation"}
    return {"e164": number, "country": None, "valid": None}


@module("phone", "Phone Number", ["phone"],
        "Validity, country, carrier, line type and time zone.", order=5)
def phone(number):
    if phonenumbers is None:
        return fallback(number)
    try:
        parsed = phonenumbers.parse(number, None if number.startswith("+") else "US")
    except phonenumbers.NumberParseException as exc:
        raise ModuleError(f"Could not parse number: {exc}")
    fmt = phonenumbers.PhoneNumberFormat
    return {
        "e164": phonenumbers.format_number(parsed, fmt.E164),
        "international": phonenumbers.format_number(parsed, fmt.INTERNATIONAL),
        "national": phonenumbers.format_number(parsed, fmt.NATIONAL),
        "calling_code": f"+{parsed.country_code}",
        "region": phonenumbers.region_code_for_number(parsed),
        "country": geocoder.country_name_for_number(parsed, "en") or None,
        "location": geocoder.description_for_number(parsed, "en") or None,
        "carrier": carrier.name_for_number(parsed, "en") or None,
        "line_type": LINE_TYPES.get(phonenumbers.number_type(parsed), "Unknown"),
        "timezones": list(pn_timezone.time_zones_for_number(parsed)),
        "valid": phonenumbers.is_valid_number(parsed),
        "possible": phonenumbers.is_possible_number(parsed),
        "assumed_region": None if number.startswith("+") else "US",
    }
