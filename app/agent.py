import hashlib

PERSONA_MAP = {
    "phishing": "naive_student",        # "naive_student" -> correct
    "otp_fraud": "confused_user",       # "confused_user" -> user requested
    "upi_refund": "elderly_user",       # "elderly_user" -> user requested
    "job_scam": "desperate_job_seeker", # "desperate_job_seeker" -> correct
    "loan_scam": "small_business_owner",# "small_business_owner" -> user requested
    "impersonation": "scared_citizen",  # "scared_citizen" -> user requested
    "unknown": "elderly_user"
}

# Templates: TEMPLATES[scam_type][stage] = [list of strings]
# Stages: hook, trust_building, extraction, exit
TEMPLATES = {
    "phishing": {
        "hook": [
            "Wait, is this actually for real?",
            "Huh? I didn't know about this. Tell me more.",
            "Yo, is this legit? I've been hacked before."
        ],
        "trust_building": [
            "I use my dad's credit card, so I gotta be careful.",
            "My professor warned me about links, but this looks diff.",
            "I'm super broke right now, so if this works, it's a lifesaver."
        ],
        "extraction": [
            "Okay, what's the link I need to click? Send it.",
            "Do you need my UPI ID or something? What is it?",
            "Just tell me exactly where to pay.",
            "Send me the URL one more time? I lost it.",
            "Is there a specific validation link? Send it here."
        ],
        "exit": [
            "Nah, this feels fake. Bye.",
            "Bored now. Don't text back.",
            "Blocking u. Weirdo."
        ]
    },
    "otp_fraud": {
        "hook": [
            "Hello? Is this my grandson? I lost my glasses.",
            "Who is this? Are you from the bank?",
            "Oh dear, I am not very good with these technical things."
        ],
        "trust_building": [
            "I don't want to lose my pension money. Please help.",
            "You sound like a nice young man. Thank you for helping.",
            "Yes, I am listening. Please don't be angry with me."
        ],
        "extraction": [
            "I got a code on my phone. Where do I send it to you?",
            "Do you need the OTP number? Or should I forward the message?",
            "I can see a number. Should I read it to you?",
            "Wait, sending the code. What number should I send it to?",
            "Okay, I have the 4-digit code. Tell me where to put it."
        ],
        "exit": [
            "I am calling the police now.",
            "My son just came home, talk to him.",
            "Stop calling me!"
        ]
    },
    "upi_refund": {
        "hook": [
            "Refund? For which order? I have a shop to run.",
            "Is this regarding the customer payment pending?",
            "Yes, I was expecting a payment. Is this it?"
        ],
        "trust_building": [
            "I handle many transactions daily, please clarify.",
            "Okay, I trust you, just guide me quickly.",
            "I don't clear payments usually, but if it's a refund ok."
        ],
        "extraction": [
            "Send me your UPI ID so I can request the money.",
            "Which QR code should I scan? Send it here.",
            "Send the payment link/address, I will check.",
            "Give me the UPI ID to complete the request.",
            "I need the VPA address to verify the refund."
        ],
        "exit": [
            "You are a scammer! I know this trick.",
            "I recorded this call. Police coming.",
            "Get lost."
        ]
    },
    "job_scam": {
        "hook": [
            "Omg really? I've been applying everywhere!",
            "Is this for the part-time remote role?",
            "I need this job desperately. Please tell me details."
        ],
        "trust_building": [
            "I can start immediately. I am hard working.",
            "Do I need to pay for training? I hope not.",
            "I sent my resume yesterday. Did you see it?"
        ],
        "extraction": [
            "Where do I sign up? Send the registration link.",
            "Do you need my bank details for salary deposit? Which one?",
            "Who should I contact? Give me the HR number.",
            "Is there a form to fill? Please share the URL.",
            "I can pay the registration fee. Send me the account details."
        ],
        "exit": [
            "Asking for money for a job? Scam.",
            "Reported this number.",
            "Not interested anymore."
        ]
    },
    "loan_scam": {
        "hook": [
            "Is this about my loan application? I need it approved.",
            "Yes, I am in debt. Can you help me?",
            "What is the interest rate? I need cash urgent."
        ],
        "trust_building": [
            "I have bad CIBIL score, will it verify?",
            "Please sir, approve it. I need money for hospital.",
            "I promise to pay back on time."
        ],
        "extraction": [
            "Where to pay the processing fee? Send account number.",
            "Do you need my Bank details or IFSC? Tell me.",
            "Send me the approval link please, I will click.",
            "Should I transfer the fee? Give me the UPI ID.",
            "Provide the bank account to deposit the insurance fee."
        ],
        "exit": [
            "You are cheating poor people!",
            "I am going to the bank branch to complain.",
            "Stop."
        ]
    },
    "impersonation": {
        "hook": [
            "Huh? Who is this? I don't recognize the number.",
            "Is that you Dave? You changed your number?",
            "Sorry, I am confused. Who are you?"
        ],
        "trust_building": [
            "Oh sorry, I didn't save your contact.",
            "Yeah, long time no see. How are you?",
            "I thought something happened to you."
        ],
        "extraction": [
            "Do you need me to GPay you? Which number/ID?",
            "Where are you stuck? Send location link or number.",
            "Send me the account details, I'll help immediately.",
            "What is your badge number or case ID? Tell me.",
            "Give me the official UPI ID to pay the fine."
        ],
        "exit": [
            "Wait, this isn't Dave. Who are you?",
            "Liar. I just called the real person.",
            "Blocked."
        ]
    },
    "unknown": {
        "hook": [
            "Hello? Who is calling?",
            "I did not understand the message.",
            "What is this regarding?"
        ],
        "trust_building": [
            "Okay, tell me more.",
            "I am listening.",
            "Is this important?"
        ],
        "extraction": [
            "What do you want me to do?",
            "Send me the details/link.",
            "Do I need to pay? Where?"
        ],
        "exit": [
            "Stop text me.",
            "Spam.",
            "Bye."
        ]
    }
}

def select_persona(scam_type: str) -> str:
    """
    Selects the appropriate persona ID based on the detected scam type.
    """
    return PERSONA_MAP.get(scam_type, "elderly_user") 

def generate_response(scam_type: str, stage: str, session_id: str, turn: int) -> tuple[str, str]:
    """
    Generates a persona-based response.
    Returns (persona_id, message).
    Deterministic selection based on session_id + turn.
    """
    persona = select_persona(scam_type)
    
    # Fallback if scam_type or stage not found
    scam_templates = TEMPLATES.get(scam_type, TEMPLATES["unknown"])
    stage_templates = scam_templates.get(stage, scam_templates["exit"])
    
    # Deterministic selection
    hash_input = f"{session_id}-{turn}".encode()
    hash_val = int(hashlib.sha256(hash_input).hexdigest(), 16)
    selected_index = hash_val % len(stage_templates)
    
    message = stage_templates[selected_index]
    
    return persona, message
