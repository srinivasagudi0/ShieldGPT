SUSPICIOUS_TLDS = {
    "zip",
    "click",
    "top",
    "xyz",
    "link",
    "rest",
    "country",
    "kim",
    "cricket",
    "work",
    "gq",
    "tk",
    "ml",
    "cf",
    "support",
    "accountant",
    "download",
    "help",
    "loan",
    "click",
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "cutt.ly",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "is.gd",
    "soo.gd",
    "shorte.st",
}

KNOWN_BRANDS = {
    "paypal",
    "apple",
    "microsoft",
    "google",
    "amazon",
    "meta",
    "facebook",
    "instagram",
    "tiktok",
    "netflix",
    "bankofamerica",
    "wellsfargo",
    "chase",
    "capitalone",
    "stripe",
    "square",
}

URGENCY_PATTERNS = [
    {"pattern": r"act now", "category": "urgency", "severity": 0.8, "explanation": "Creates artificial time pressure"},
    {"pattern": r"immediately", "category": "urgency", "severity": 0.7, "explanation": "Demands instant action"},
    {"pattern": r"urgent", "category": "urgency", "severity": 0.8, "explanation": "Sets a high-pressure tone"},
    {"pattern": r"right away", "category": "urgency", "severity": 0.6, "explanation": "Pushes immediate response"},
    {"pattern": r"last chance", "category": "urgency", "severity": 0.7, "explanation": "Manufactures scarcity"},
    {"pattern": r"final notice", "category": "urgency", "severity": 0.7, "explanation": "Implied consequence if ignored"},
    {"pattern": r"verify now", "category": "urgency", "severity": 0.8, "explanation": "Forces rushed verification"},
    {"pattern": r"respond now", "category": "urgency", "severity": 0.7, "explanation": "Pressures immediate reply"},
]

MANIPULATION_PATTERNS = [
    {"pattern": r"unusual activity", "category": "content", "severity": 0.7, "explanation": "Fear trigger for account compromise"},
    {"pattern": r"account (locked|suspended|hold)", "category": "content", "severity": 0.8, "explanation": "Claims account lockdown to force action"},
    {"pattern": r"security alert", "category": "content", "severity": 0.7, "explanation": "Spoofs security notifications"},
    {"pattern": r"reset (your )?password", "category": "content", "severity": 0.8, "explanation": "Tries to capture credentials"},
    {"pattern": r"confirm (your )?identity", "category": "content", "severity": 0.7, "explanation": "Attempts to harvest PII"},
    {"pattern": r"verify (your )?(account|payment)", "category": "content", "severity": 0.7, "explanation": "Pushes fake verification flow"},
    {"pattern": r"gift card", "category": "content", "severity": 0.9, "explanation": "Classic payment red flag"},
    {"pattern": r"crypto", "category": "content", "severity": 0.8, "explanation": "Often tied to irreversible payments"},
    {"pattern": r"bitcoin", "category": "content", "severity": 0.8, "explanation": "High-risk irreversible transfers"},
    {"pattern": r"wire transfer", "category": "content", "severity": 0.8, "explanation": "Attempts to reroute funds"},
    {"pattern": r"prepaid card", "category": "content", "severity": 0.9, "explanation": "Untraceable payment request"},
    {"pattern": r"prize", "category": "content", "severity": 0.6, "explanation": "Lures with fake winnings"},
    {"pattern": r"lottery", "category": "content", "severity": 0.6, "explanation": "Common sweepstakes scam lure"},
    {"pattern": r"invoice", "category": "content", "severity": 0.6, "explanation": "Spoofs billing to collect payments"},
    {"pattern": r"payment immediately", "category": "content", "severity": 0.8, "explanation": "Payment with urgency is high-risk"},
]

SPOOF_PATTERNS = [
    {"pattern": r"support (team|desk)", "category": "spoofing", "severity": 0.7, "explanation": "Poses as official support"},
    {"pattern": r"customer (service|support)", "category": "spoofing", "severity": 0.7, "explanation": "Impersonates customer support"},
    {"pattern": r"it (help|desk)", "category": "spoofing", "severity": 0.6, "explanation": "Claims internal IT authority"},
    {"pattern": r"fraud department", "category": "spoofing", "severity": 0.8, "explanation": "Masquerades as fraud team"},
    {"pattern": r"security team", "category": "spoofing", "severity": 0.7, "explanation": "Feigns security credentials"},
    {"pattern": r"official notice", "category": "spoofing", "severity": 0.6, "explanation": "Attempts to look formal/official"},
]

PERSONAL_INFO_PATTERNS = [
    r"social security",
    r"ssn",
    r"passport",
    r"driver.?s license",
    r"date of birth",
    r"account number",
    r"routing number",
    r"credit card",
    r"debit card",
    r"cvv",
    r"security code",
]

PAYMENT_PRESSURE_PATTERNS = [
    r"wire transfer",
    r"bank transfer",
    r"gift card",
    r"crypto",
    r"bitcoin",
    r"ethereum",
    r"wallet",
    r"payment (now|immediately|today)",
    r"pay (now|immediately|today)",
    r"fee required",
    r"processing fee",
    r"deposit",
    r"advance fee",
    r"cash app",
    r"venmo",
    r"zelle",
]

SAFE_ACTIONS = [
    "Do not click links until verified through official channels.",
    "Avoid sharing passwords, MFA codes, or personal details.",
    "If the message claims to be a known brand, contact them via their official site or app.",
    "Run a password reset on the real site if you suspect compromise.",
    "Enable MFA on affected accounts.",
    "Report the message to the platform or provider.",
    "Scan your device with updated antivirus if you interacted with the link.",
]

SAFE_REPLIES = [
    "I cannot proceed. Please contact me through your official website or support channel.",
    "I do not share personal or payment information over messages. I will verify independently.",
    "For security, I will log in directly via the official site to confirm any issues.",
    "I only engage using verified domains and official apps. Please provide a legitimate contact method.",
]

# Categories for context-aware responses and pattern tagging
CATEGORY_PATTERNS = {
    "banking": [
        r"bank",
        r"account (locked|suspended)",
        r"card (locked|blocked)",
        r"fraud (alert|team)",
    ],
    "delivery": [
        r"package",
        r"delivery",
        r"courier",
        r"shipping",
        r"customs",
        r"reschedule",
    ],
    "job_offer": [
        r"job offer",
        r"remote work",
        r"signing bonus",
        r"paycheck",
        r"work from home",
        r"urgent hire",
    ],
    "crypto": [
        r"crypto",
        r"bitcoin",
        r"giveaway",
        r"airdrops?",
        r"wallet",
        r"token",
    ],
    "account_recovery": [
        r"password reset",
        r"verify account",
        r"confirm identity",
        r"2fa",
        r"mfa",
        r"unlock",
    ],
}

CATEGORY_ACTIONS = {
    "banking": [
        "Call the number on the back of your card or use the official banking app to verify.",
        "Do not share codes or PINs over the phone or SMS.",
    ],
    "delivery": [
        "Track packages only via the official courier site or retailer account.",
        "Avoid paying fees or customs through random links.",
    ],
    "job_offer": [
        "Ignore requests to pay for equipment or training upfront.",
        "Verify the company domain and recruiter identity via LinkedIn or official site.",
    ],
    "crypto": [
        "Never connect your wallet to unknown dApps or sign random messages.",
        "Ignore promises of guaranteed returns or giveaways.",
    ],
    "account_recovery": [
        "Reset your password directly on the official site/app, not via the received link.",
        "Regenerate MFA in the security settings—not through links sent over email/SMS.",
    ],
}

CATEGORY_REPLIES = {
    "banking": [
        "I will contact my bank using the number on my card/app to verify. I won’t share codes here.",
    ],
    "delivery": [
        "I will check my order status directly with the courier/retailer. I won’t pay via this link.",
    ],
    "job_offer": [
        "I’ll continue only through official company channels and won’t send payments for equipment.",
    ],
    "crypto": [
        "I don’t connect wallets or share seeds outside verified platforms. Please provide an official channel.",
    ],
    "account_recovery": [
        "I’ll reset my account directly in the official app/site. I won’t share codes over this channel.",
    ],
}
