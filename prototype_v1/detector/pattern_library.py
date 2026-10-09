"""
High-Precision Pattern Library and Checksum Validators.
Provides deterministic detection for financial instruments, government credentials, and corporate identifiers.
"""
import re
from typing import List, Dict, Any, Tuple

def luhn_checksum(card_number_str: str) -> bool:
    """Validates credit card numbers using the standard Luhn algorithm."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for idx, num in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = num * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += num
    return checksum % 10 == 0

def aba_routing_checksum(routing_str: str) -> bool:
    """Validates 9-digit US ABA routing transit numbers using standard weights (3, 7, 1)."""
    digits = [int(c) for c in routing_str if c.isdigit()]
    if len(digits) != 9:
        return False
    weights = [3, 7, 1, 3, 7, 1, 3, 7, 1]
    total = sum(d * w for d, w in zip(digits, weights))
    return total % 10 == 0

class PatternLibrary:
    # 1. Government IDs
    SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
    US_PASSPORT_PATTERN = re.compile(r'\b(?:passport[:\s#]*|[A-Z])([0-9]{8,9})\b', re.IGNORECASE)
    PASSPORT_KEYWORD_PATTERN = re.compile(r'\b(?:passport(?:\s*(?:no|number|id|#))?[:\s]+)([A-Z0-9]{8,9})\b', re.IGNORECASE)
    US_DL_PATTERN = re.compile(r'\b(?:NY-DL|DL|Driver\s*License(?:\s*#)?[:\s]+)([A-Z0-9\-]{7,12})\b', re.IGNORECASE)
    IN_PAN_PATTERN = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b')
    IN_AADHAAR_PATTERN = re.compile(r'\b[2-9][0-9]{3}\s[0-9]{4}\s[0-9]{4}\b')

    # 2. Financial & Banking
    CREDIT_CARD_PATTERN = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b3[47]\d{13}\b')
    BANK_ACCOUNT_PATTERN = re.compile(r'\b(?:ACCT|Account|Acc\s*No|Checking|Escrow|Settlement|Wire\s*Account)[:\s#-]*([0-9]{8,16})\b', re.IGNORECASE)
    BANK_ROUTING_PATTERN = re.compile(r'\b(?:Routing|ABA|RTN)[:\s#-]*([0-9]{9})\b', re.IGNORECASE)
    SWIFT_BIC_PATTERN = re.compile(r'\b(?:SWIFT|BIC)[:\s#-]*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b|\b[A-Z]{6}[A-Z0-9]{2}[A-Z0-9]{3}\b')
    IFSC_PATTERN = re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b')
    IBAN_PATTERN = re.compile(r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b')

    # 3. Direct Personal & Contact
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')
    PHONE_PATTERN = re.compile(r'(?:\+?(\d{1,3})[-.\s]?)?\(?(\d{2,4})\)?[-.\s]?(\d{3,4})[-.\s]?(\d{4})')
    DOB_PATTERN = re.compile(r'\b(?:DOB|Date of Birth|Birth Date)[:\s]+([0-9]{1,2}[\/\-][0-9]{1,2}[\/\-][0-9]{2,4}|[0-9]{1,2}\s+[A-Za-z]+\s+[0-9]{4})\b', re.IGNORECASE)
    ADDRESS_LINE_PATTERN = re.compile(r'\b\d{1,5}\s+[A-Za-z0-9\s,.-]+?\b(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Terrace|Way|Drive|Dr|Nagar|Lane|Ln|Apt|Suite)\b', re.IGNORECASE)

    # 4. Corporate & Educational Identifiers
    CADENCE_EMP_ID_PATTERN = re.compile(r'\b(?:EMP|EID|STAFF|Emp\s*ID)[:\s#-]*([0-9]{4,6})\b|\bEMP-[0-9]{4,6}\b', re.IGNORECASE)
    STUDENT_ID_PATTERN = re.compile(r'\b[0-9]{2}[A-Z]{3}[0-9]{4}\b')

    @classmethod
    def find_all_matches(cls, text: str) -> List[Dict[str, Any]]:
        matches = []

        # SSN
        for m in cls.SSN_PATTERN.finditer(text):
            matches.append({
                "entity_type": "US_SSN",
                "value": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "confidence": 1.0,
                "source": "Regex_Checksum_Engine"
            })

        # Credit Cards with Luhn validation
        for m in cls.CREDIT_CARD_PATTERN.finditer(text):
            raw_val = m.group(0)
            cleaned = "".join(filter(str.isdigit, raw_val))
            if luhn_checksum(cleaned):
                matches.append({
                    "entity_type": "CREDIT_CARD",
                    "value": raw_val,
                    "start": m.start(),
                    "end": m.end(),
                    "confidence": 1.0,
                    "source": "Regex_Checksum_Engine"
                })

        # Indian PAN
        for m in cls.IN_PAN_PATTERN.finditer(text):
            val = m.group(0)
            # 4th character represents status: P (individual), C (company), etc.
            if val[3] in "PCAFHTLJG":
                matches.append({
                    "entity_type": "IN_PAN",
                    "value": val,
                    "start": m.start(),
                    "end": m.end(),
                    "confidence": 0.98,
                    "source": "Regex_Checksum_Engine"
                })

        # Indian Aadhaar
        for m in cls.IN_AADHAAR_PATTERN.finditer(text):
            matches.append({
                "entity_type": "IN_AADHAAR",
                "value": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.95,
                "source": "Regex_Checksum_Engine"
            })

        # Bank Account Numbers
        for m in cls.BANK_ACCOUNT_PATTERN.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            s = m.start(1) if m.groups() else m.start()
            e = m.end(1) if m.groups() else m.end()
            matches.append({
                "entity_type": "BANK_ACCOUNT",
                "value": val,
                "start": s,
                "end": e,
                "confidence": 0.95,
                "source": "Cadence_Financial_Engine"
            })

        # Bank Routing Numbers
        for m in cls.BANK_ROUTING_PATTERN.finditer(text):
            val = m.group(1)
            valid = aba_routing_checksum(val)
            matches.append({
                "entity_type": "BANK_ROUTING",
                "value": val,
                "start": m.start(1),
                "end": m.end(1),
                "confidence": 0.99 if valid else 0.85,
                "source": "Regex_Checksum_Engine"
            })

        # SWIFT / BIC
        for m in cls.SWIFT_BIC_PATTERN.finditer(text):
            val = m.group(1) if m.group(1) else m.group(0)
            matches.append({
                "entity_type": "SWIFT_BIC",
                "value": val,
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.92,
                "source": "Regex_Checksum_Engine"
            })

        # IFSC Code
        for m in cls.IFSC_PATTERN.finditer(text):
            matches.append({
                "entity_type": "IFSC_CODE",
                "value": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.98,
                "source": "Regex_Checksum_Engine"
            })

        # Passports
        for m in cls.PASSPORT_KEYWORD_PATTERN.finditer(text):
            matches.append({
                "entity_type": "US_PASSPORT",
                "value": m.group(1),
                "start": m.start(1),
                "end": m.end(1),
                "confidence": 0.95,
                "source": "Cadence_Rule"
            })

        # Driver's License
        for m in cls.US_DL_PATTERN.finditer(text):
            matches.append({
                "entity_type": "US_DRIVER_LICENSE",
                "value": m.group(1),
                "start": m.start(1),
                "end": m.end(1),
                "confidence": 0.92,
                "source": "Cadence_Rule"
            })

        # Employee IDs
        for m in cls.CADENCE_EMP_ID_PATTERN.finditer(text):
            matches.append({
                "entity_type": "EMPLOYEE_ID",
                "value": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.95,
                "source": "Cadence_Corporate_Engine"
            })

        # Student IDs
        for m in cls.STUDENT_ID_PATTERN.finditer(text):
            matches.append({
                "entity_type": "STUDENT_ID",
                "value": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.90,
                "source": "Regex_Checksum_Engine"
            })

        # Date of Birth
        for m in cls.DOB_PATTERN.finditer(text):
            matches.append({
                "entity_type": "DATE_OF_BIRTH",
                "value": m.group(1),
                "start": m.start(1),
                "end": m.end(1),
                "confidence": 0.95,
                "source": "Cadence_Rule"
            })

        # Emails
        for m in cls.EMAIL_PATTERN.finditer(text):
            matches.append({
                "entity_type": "EMAIL_ADDRESS",
                "value": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "confidence": 1.0,
                "source": "Regex_Checksum_Engine"
            })

        # Phones (filter out simple 4 digit numbers or dates)
        for m in cls.PHONE_PATTERN.finditer(text):
            val = m.group(0).strip()
            digits = "".join(filter(str.isdigit, val))
            if len(digits) >= 10:
                matches.append({
                    "entity_type": "PHONE_NUMBER",
                    "value": val,
                    "start": m.start(),
                    "end": m.end(),
                    "confidence": 0.90,
                    "source": "Regex_Checksum_Engine"
                })

        # Street Addresses
        for m in cls.ADDRESS_LINE_PATTERN.finditer(text):
            matches.append({
                "entity_type": "STREET_ADDRESS",
                "value": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.85,
                "source": "Cadence_Contextual_Engine"
            })

        return matches
