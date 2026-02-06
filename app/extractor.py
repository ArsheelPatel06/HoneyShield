import re

def extract_upi_ids(text: str) -> list[str]:
    # Matches typical UPI pattern: username@bank
    pattern = r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}'
    return list(set(re.findall(pattern, text)))

def extract_urls(text: str) -> list[str]:
    # Matches http/https URLs
    # Simplified pattern to catch most common links
    pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w./?%&=]*)?'
    return list(set(re.findall(pattern, text)))

def extract_phone_numbers(text: str) -> list[str]:
    # Matches: +91 9999988888, 9999988888, 999-999-9999
    # BUT must avoid matching long bank account numbers (12+ digits)
    
    # Strategy: 
    # 1. Identify all digit sequences.
    # 2. If > 11 digits and no separators (+, -), ignore (likely bank).
    # 3. If valid phone pattern, keep.
    
    # Regex explanation:
    # (?<!\d) : ensure we are at start of number
    # (?:(?:\+|0{0,2})91[\-\s]?)? : optional +91 or 091 prefix
    # [6-9]\d{9} : 10 digit mobile starting with 6-9
    # (?!\d) : ensure we end at 10 digits
    indian_mobile_pattern = r'(?<!\d)(?:(?:\+|0{0,2})91[\-\s]?)?[6-9]\d{9}(?!\d)'
    
    # Generic Pattern (e.g. +1-555...)
    # Min 10, Max 15 digits including separators.
    # We must be careful not to match a substring of a 12 digit number.
    
    matches = []
    
    # 1. High confidence Indian mobile
    matches.extend(re.findall(indian_mobile_pattern, text))
    
    # 2. Generic matches, but filter out pure long digits
    # Pattern: Optional +code, then space/dash, then digits
    generic = r'(?<!\d)\+?\d{1,4}[-.\s]?\(?\d{2,3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)'
    candidates = re.findall(generic, text)
    
    for c in candidates:
        digits = re.sub(r'\D', '', c)
        if 10 <= len(digits) <= 11: # Strictly 10-11 for generic phones to avoid bank collision
            matches.append(c)
            
    return list(set(matches))

def extract_bank_accounts(text: str) -> list[str]:
    # Strategy:
    # 1. Find purely numeric sequences of 9-18 digits.
    # 2. If matches a phone number found by extract_phone_numbers, DISCARD.
    # 3. If 12-18 digits -> Accept (Bank)
    # 4. If 9-11 digits -> Accept ONLY if context found (account, bank, etc)
    
    # Get phones first to filter them out
    phones = extract_phone_numbers(text)
    phone_digits = set(re.sub(r'\D', '', p) for p in phones)
    
    # Regex for potential bank numbers (pure digits only to avoid collision with formatted phones)
    # Bank accounts usually don't have dashes/spaces in scams, usually raw digits
    pattern = r'\b\d{9,18}\b'
    matches = list(re.finditer(pattern, text))
    
    results = []
    keywords = ["account", "a/c", "acc", "bank", "acct", "number", "no.", "ifsc"]
    
    for match in matches:
        candidate = match.group()
        
        # Overlap check
        if candidate in phone_digits:
            continue
            
        if len(candidate) >= 12:
            results.append(candidate)
        else:
             # Context check for 9-11 digits
            start, end = match.span()
            pre_text = text[max(0, start - 50):start].lower()
            if any(k in pre_text for k in keywords):
                results.append(candidate)
                
    return list(set(results))
