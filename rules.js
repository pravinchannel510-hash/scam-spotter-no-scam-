/**
 * Scam Spotter - Rule Engine & Brand Database
 * Transparent, explainable scoring with zero black-box obscurity.
 */

// Default point weights for the 11 detection rules (total capped at 100)
const DEFAULT_POINTS = {
  sender: 25,     // Hard: Fake sender or free webmail posing as an organisation
  urgency: 20,    // Soft: Artificial rush & pressure
  threat: 15,     // Soft: Account suspension, disconnection, legal action threats
  link: 25,       // Hard: Phishing, lookalike, shortened, or unverified link
  creds: 40,      // Hard: Demanding OTP, UPI PIN, password, or card CVV
  money: 35,      // Hard: Upfront fee, advance deposit, or deceptive UPI collect
  reward: 20,     // Soft: Too-good-to-be-true rewards, lottery, work-from-home scams
  authority: 35,  // Hard: Impersonating police, CBI, customs, or "digital arrest"
  secrecy: 15,    // Soft: Demands to hide from family, stay on video call
  install: 35,    // Hard: Remote access tools (AnyDesk), APKs, dangerous attachments
  callback: 15    // Soft: Unofficial mobile phone or WhatsApp callback trap
};

const RULE_ORDER = ['sender', 'urgency', 'threat', 'link', 'creds', 'money', 'reward', 'authority', 'secrecy', 'install', 'callback'];

// Hard signs represent active pathways to financial or credential theft.
// Soft signs represent emotional manipulation.
const HARD_RULES = new Set(['sender', 'link', 'creds', 'money', 'authority', 'install']);

const RISK_THRESHOLDS = {
  lowMax: 29,      // 0 - 29: Low Risk
  mediumMax: 59,   // 30 - 59: Medium Risk
  highMin: 60      // 60 - 100: High Risk
};

// Known brands & their official domains in India & Global services
const KNOWN_BRANDS = {
  sbi: {
    name: 'State Bank of India (SBI)',
    keys: ['sbi', 'onlinesbi', 'yono'],
    domains: ['sbi.co.in', 'onlinesbi.sbi', 'bank.sbi', 'sbicard.com', 'sbilife.co.in']
  },
  hdfc: {
    name: 'HDFC Bank',
    keys: ['hdfc', 'hdfcbank'],
    domains: ['hdfcbank.com', 'hdfc.com', 'hdfclife.com', 'hdfcergo.com']
  },
  icici: {
    name: 'ICICI Bank',
    keys: ['icici', 'icicibank'],
    domains: ['icicibank.com', 'icicilombard.com', 'iciciprulife.com']
  },
  axis: {
    name: 'Axis Bank',
    keys: ['axis', 'axisbank'],
    domains: ['axisbank.com', 'axisbank.co.in']
  },
  kotak: {
    name: 'Kotak Mahindra Bank',
    keys: ['kotak'],
    domains: ['kotak.com', 'kotaksecurities.com']
  },
  paytm: {
    name: 'Paytm',
    keys: ['paytm'],
    domains: ['paytm.com', 'paytmbank.com']
  },
  phonepe: {
    name: 'PhonePe',
    keys: ['phonepe'],
    domains: ['phonepe.com']
  },
  google: {
    name: 'Google / Gmail',
    keys: ['google', 'gmail'],
    domains: ['google.com', 'google.co.in', 'gmail.com', 'accounts.google.com']
  },
  microsoft: {
    name: 'Microsoft',
    keys: ['microsoft', 'outlook', 'office365'],
    domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com']
  },
  amazon: {
    name: 'Amazon',
    keys: ['amazon', 'amazonpay'],
    domains: ['amazon.in', 'amazon.com', 'amazonpay.in']
  },
  flipkart: {
    name: 'Flipkart',
    keys: ['flipkart'],
    domains: ['flipkart.com']
  },
  indiapost: {
    name: 'India Post',
    keys: ['indiapost', 'speedpost'],
    domains: ['indiapost.gov.in', 'postoffice.gov.in']
  },
  bluedart: {
    name: 'Blue Dart',
    keys: ['bluedart'],
    domains: ['bluedart.com']
  },
  dtdc: {
    name: 'DTDC Courier',
    keys: ['dtdc'],
    domains: ['dtdc.com', 'dtdc.in']
  },
  delhivery: {
    name: 'Delhivery',
    keys: ['delhivery'],
    domains: ['delhivery.com']
  },
  uidai: {
    name: 'UIDAI (Aadhaar)',
    keys: ['uidai', 'aadhaar'],
    domains: ['uidai.gov.in', 'myaadhaar.uidai.gov.in']
  },
  incometax: {
    name: 'Income Tax Department',
    keys: ['incometax', 'tin-nsdl'],
    domains: ['incometax.gov.in', 'incometaxindia.gov.in', 'tin-nsdl.com']
  },
  jio: {
    name: 'Jio',
    keys: ['jio'],
    domains: ['jio.com', 'jiomart.com']
  },
  airtel: {
    name: 'Airtel',
    keys: ['airtel'],
    domains: ['airtel.in', 'airtel.com']
  },
  netflix: {
    name: 'Netflix',
    keys: ['netflix'],
    domains: ['netflix.com']
  },
  pnb: {
    name: 'Punjab National Bank (PNB)',
    keys: ['pnb', 'punjabnational'],
    domains: ['pnbindia.in', 'netpnb.com']
  },
  bob: {
    name: 'Bank of Baroda',
    keys: ['bob', 'bankofbaroda'],
    domains: ['bankofbaroda.in', 'bankofbaroda.com', 'bobworld.com']
  },
  canara: {
    name: 'Canara Bank',
    keys: ['canara', 'canarabank'],
    domains: ['canarabank.com', 'canarabank.in']
  },
  unionbank: {
    name: 'Union Bank of India',
    keys: ['unionbank'],
    domains: ['unionbankofindia.co.in', 'unionbankonline.co.in']
  },
  meesho: {
    name: 'Meesho',
    keys: ['meesho'],
    domains: ['meesho.com']
  },
  epfo: {
    name: 'EPFO (Provident Fund)',
    keys: ['epfo', 'epfindia'],
    domains: ['epfindia.gov.in', 'unifiedportal-mem.epfindia.gov.in']
  },
  irctc: {
    name: 'IRCTC (Indian Railways)',
    keys: ['irctc'],
    domains: ['irctc.co.in']
  },
  whatsapp: {
    name: 'WhatsApp',
    keys: ['whatsapp'],
    domains: ['whatsapp.com', 'wa.me']
  }
};

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'cutt.ly', 'rb.gy', 'is.gd',
  'shorturl.at', 'ow.ly', 'bitly.com', 'tiny.cc', 'buff.ly', 't.ly'
]);

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'click', 'live', 'icu', 'buzz', 'tk', 'vip', 'link',
  'online', 'site', 'shop', 'cf', 'ga', 'ml', 'gq', 'work', 'cc', 'rest'
]);

const FREE_EMAIL_PROVIDERS = new Set([
  'gmail.com', 'yahoo.com', 'yahoo.co.in', 'outlook.com', 'hotmail.com',
  'rediffmail.com', 'proton.me', 'protonmail.com', 'mail.com', 'yandex.com'
]);

// Regular Expressions for Detection
const URL_REGEX = /\b(?:https?:\/\/|www\.)[^\s<>"'`)\]]+|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.(?:com|in|net|org|co|io|me|xyz|top|click|live|icu|buzz|tk|link|info|online|site|shop|vip|gov|edu|example|app|ly|gl|to|cc|sbi|bank)\b(?:\/[^\s<>"'`)\]]*)?/gi;

const URGENCY_REGEX = /\b(?:today|tonight|immediately|urgent(?:ly)?|right now|asap|at once|act now|hurry|without delay|before midnight|expires? (?:today|tonight|soon)|(?:in|within) (?:the next )?\d+\s*(?:hours?|hrs?|minutes?|mins?)|last (?:chance|warning)|final (?:notice|warning|reminder)|limited (?:time|slots|seats|offer)|only \d+ (?:slots?|seats?)(?: left)?|offer ends|turant|jaldi se|abhi|aaj hi|24 ghante mein)\b/gi;

const THREAT_REGEX = /\b(?:(?:account|card|sim|number|service|connection|electricity|power supply|gas|wallet|upi|kyc|pan|aadhaar|mailbox|membership|id)\b[^.!?\n]{0,55}?\b(?:will be|is being|has been|gets|shall be|to be)\s+(?:blocked|suspended|deactivated|disabled|closed|frozen|locked|cancelled|terminated|disconnected)|kyc\b[^.!?\n]{0,35}?\b(?:incomplete|pending|expired|not updated|not complete|not done)|legal action|(?:will be|be) (?:arrested|prosecuted|fined|jailed)|(?:avoid|face|facing) (?:arrest|legal action|prosecution|disconnection|suspension|blocking|closure|penalty|late fee)|arrest warrant|permanently (?:blocked|banned)|(?:account|kyc|card|sim)[^.!?\n]{0,30}\b(?:band|block|suspend) ho)\b/gi;

const STRONG_VERBS = 'share|send|tell|provide|give|forward|reply with|read out|disclose|submit|reveal|batao|bataiye|bhejo|bhejiye';
const SOFT_VERBS = 'enter|confirm|verify|update|type|re-?enter|validate|login with|log in with';
const CREDENTIAL_ITEMS = 'otp|one[- ]time password|verification code|upi pin|mpin|pin(?!\\s?code)|password|passcode|cvv|card number|card details|debit card|credit card|net ?banking(?: id| password| details)?|login details|credentials|aadhaar number|pan number|security code';
const CREDS_REGEX = new RegExp('\\b(' + STRONG_VERBS + '|' + SOFT_VERBS + ')\\b[^.!?\\n]{0,45}?\\b(' + CREDENTIAL_ITEMS + ')\\b', 'gi');
const CREDS_HINGLISH_REGEX = /\b(?:otp|pin|password|cvv)\b[^.!?\n]{0,20}?\b(?:batao|bataiye|bhejo|bhejiye|dijiye|share karo|send karo)\b/gi;
const NEGATION_BEFORE_REGEX = /\b(?:do not|don'?t|dont|never|not|no one|nobody|won'?t|will not|cannot|can'?t)\b\s*(?:\w+\s+){0,4}$/i;

const MONEY_REGEX = /\b(?:processing|registration|customs|delivery|clearance|release|security|refundable|advance|activation|verification|re-?delivery|handling|insurance|admin|training)\s+(?:fee|fees|charges?|deposit|duty)\b|\b(?:customs )?(?:duty|charges?|fees?)\b[^.!?\n]{0,25}\b(?:is|are) (?:pending|due|unpaid|overdue)\b|\b(?:safe|secure|escrow|rbi|verification) account\b|\b(?:pay|send|transfer|deposit|remit)\b[^.!?\n]{0,30}?(?:₹|\b(?:rs|inr)\.?)\s?[\d,]+|\b(?:approve|accept)\b[^.!?\n]{0,25}?\b(?:collect|payment request|money request)\b|\bupi (?:collect|request)\b|\bscan\b[^.!?\n]{0,15}\bqr\b|\bgift cards?\b|\bsend (?:money|funds)\b|\bwire transfer\b/gi;

const REWARD_REGEX = /\b(?:you (?:have )?(?:won|been selected)|congratulations|lucky (?:winner|draw|customer)|lottery|jackpot|prize|free (?:gift|iphone|recharge|laptop)|cashback of|claim your \w+|refund (?:of|is)|earn (?:₹|rs\.?)\s?[\d,]+\s*(?:per|a|\/)\s*(?:day|hour|week)|work(?:ing)? from home|part[- ]time job|guaranteed (?:income|returns?|profit)|double your money|like youtube videos)\b/gi;

const AUTHORITY_REGEX = /\b(?:(?:cbi|ncb|narcotics|customs(?: department| officer| office)?|police|cyber ?crime(?: branch| cell| police)?|enforcement directorate|ed|income tax (?:department|officer)|trai|rbi|court|supreme court|inspector)\b[\s\S]{0,140}?\b(?:parcel|package|courier|drugs?|illegal|laundering|misused|linked to|case|warrant|arrest|video call|skype|fir)\b|digital arrest)/gi;

const SECRECY_REGEX = /\b(?:(?:do not|don'?t|dont|never)\s+(?:tell|inform|disconnect|cut the call|hang up)\b[^.!?\n]{0,35}|keep (?:this|it) (?:confidential|secret|private)\b|stay (?:on|in) (?:the )?(?:video )?call\b|not to tell anyone\b|do not (?:contact|talk to) (?:anyone|your family)\b)/gi;

const CALLBACK_REGEX = /\b(?:call|whatsapp|message|contact|dial)\b[^.!?\n]{0,25}\b(?:this|our) (?:officer|number|agent|executive|helpline|customer care)\b|\b(?:call|whatsapp|dial)\b[^.!?\n]{0,25}(?:\+91[- ]?)?\b[6-9]\d{9}\b/gi;

const INSTALL_REGEX = /\b(?:(?:install|download)\b[^.!?\n]{0,40}?\bapp\b(?:\s+(?:from|at|via|using)|:)?(?=\s*(?:https?:\/\/|www\.))|(?:install|download|open)\b[^.!?\n]{0,40}?\b(?:apk|anydesk|teamviewer|quicksupport|rustdesk|remote (?:access|support|desktop)|screen shar(?:e|ing))\b|(?:anydesk|teamviewer|quicksupport|rustdesk)\b|[\w-]+\.(?:apk|zip|exe|scr|vbs|iso|rar|jar|bat|html?)\b|enable (?:content|macros?)\b)/gi;

// Hindi / Indic Script RegEx
const INDIC_URGENCY = /(?:तुरंत|आज ही|अभी|२४ घंटे में)/g;
const INDIC_THREAT = /(?:खाता|अकाउंट)[^।.!?\n]{0,20}(?:बंद|ब्लॉक|सस्पेंड)|केवाईसी[^।.!?\n]{0,20}(?:अधूरा|अपडेट)/g;
const INDIC_CREDS = /(?:ओटीपी|पिन|पासवर्ड|सीवीवी)[^।.!?\n]{0,20}(?:बताएं|बताइए|भेजें|शेयर|दें)/g;

// Rule Explanations and Plain Language Rationale
const RULE_METADATA = {
  sender: {
    name: 'Fake or Unofficial Sender',
    rule: 'The From address belongs to a free email provider (e.g., @gmail.com) pretending to be a company or government agency, or domain does not match.',
    why: 'Official organisations never send security notices or account warnings from personal Gmail or Yahoo addresses.',
    hard: true
  },
  urgency: {
    name: 'Artificial Urgency',
    rule: 'Pressure phrases like "today", "immediately", "within 24 hours", or "last warning".',
    why: 'Scammers rush you into making a hasty decision before you have time to consult your family or bank.',
    hard: false
  },
  threat: {
    name: 'Threat of Immediate Penalty',
    rule: 'Threatening to block your bank account, cut off electricity, suspend your SIM card, or issue an arrest warrant.',
    why: 'Fear of losing essential services causes panic and forces victims into impulsive compliance.',
    hard: false
  },
  link: {
    name: 'Suspicious or Lookalike Link',
    rule: 'Unverified links, shortened links (bit.ly/tinyurl), or domains with deceptive subdomains mimicking real brands.',
    why: 'Clicking fake links opens phishing websites designed to clone login portals and harvest your credentials.',
    hard: true
  },
  creds: {
    name: 'Request for OTP, PIN, or Password',
    rule: 'Asking you to reveal, send, or submit a one-time password (OTP), UPI PIN, card CVV, or netbanking credentials.',
    why: 'Legitimate banks and tech firms will never ask you to reveal an OTP. Sharing it lets scammers drain your funds.',
    hard: true
  },
  money: {
    name: 'Demanding Upfront Payment or UPI Collect',
    rule: 'Asking for "customs clearance", "security deposit", "registration fee", or prompting you to approve a UPI collect request.',
    why: 'You never have to enter your UPI PIN or pay money to receive a prize, delivery, or job offer.',
    hard: true
  },
  reward: {
    name: 'Unrealistic Reward or Job Offer',
    rule: 'Lottery winnings, cashback rewards, or lucrative work-from-home jobs paying thousands daily for simple clicks.',
    why: 'Too-good-to-be-true promises are lures used to trap job seekers and students into paying registration fees.',
    hard: false
  },
  authority: {
    name: 'Impersonating Police, CBI, or Court',
    rule: 'Claims by "Police", "Customs", "CBI", or "NCB" alleging an illegal courier and demanding a "digital arrest" video call.',
    why: 'Law enforcement agencies never conduct interrogations or demand money transfers over Skype/WhatsApp video calls.',
    hard: true
  },
  secrecy: {
    name: 'Isolation & Secrecy Demands',
    rule: 'Instructions saying "do not tell anyone", "keep this secret", or "stay on the call without disconnecting".',
    why: 'Scammers deliberately isolate you so knowledgeable friends or family members cannot step in to protect you.',
    hard: false
  },
  install: {
    name: 'Dangerous App, APK, or Remote Access',
    rule: 'Instructions to download APK files or install screen-sharing tools like AnyDesk, TeamViewer, or QuickSupport.',
    why: 'Remote access software allows criminals to view your screen, read your incoming SMS OTPs, and take full control.',
    hard: true
  },
  callback: {
    name: 'Unofficial Phone or WhatsApp Contact',
    rule: 'Directing you to call an unofficial mobile number or message a private WhatsApp number for urgent resolution.',
    why: 'The phone number connects directly to the scammer rather than the certified helpline of the company.',
    hard: false
  }
};

// Safe Sign Messages
const SAFE_SIGNALS = {
  official_link: host => `Official verified domain detected: "${host}".`,
  official_sender: extra => `Sender email matches the certified domain (${extra}).`,
  otp_delivery: () => 'The message only delivers a code you initiated; it does NOT ask you to share it.',
  warn_share: () => 'The message explicitly warns you never to share OTPs or credentials.'
};

// Multi-Language Explanations (English, Hindi, Hinglish)
const UI_TRANSLATIONS = {
  en: {
    highTitle: 'High Risk. Danger detected — do NOT act on this message.',
    highDesc: 'Multiple warning signs were detected, including direct risks of financial loss, account theft, or credential harvesting. Do not click links, make payments, or reveal codes.',
    medTitle: 'Medium Risk. Be cautious — verify through official channels.',
    medDesc: 'Some suspicious signs were detected. While it could be a routine reminder, never open unverified links. Always check inside the official app or website directly.',
    lowZeroTitle: 'Low Risk. No warning signs matched.',
    lowZeroDesc: 'The message did not match known scam patterns. However, always exercise caution if an unexpected request arrives.',
    lowMildTitle: 'Low Risk. Only mild or routine signs detected.',
    lowMildDesc: 'The signals found are weak or typical of legitimate notifications. Soft signs alone do not indicate an active attack.',
    safeNextSteps: 'Safe Next Steps'
  },
  hi: {
    highTitle: 'उच्च जोखिम (High Risk)। इस संदेश पर कोई कार्रवाई न करें!',
    highDesc: 'इस संदेश में कई खतरनाक संकेत पाए गए हैं, जिससे आपका पैसा या खाता चोरी हो सकता है। किसी लिंक पर क्लिक न करें, भुगतान न करें, और कोई कोड साझा न करें।',
    medTitle: 'मध्यम जोखिम (Medium Risk)। सावधान रहें — आधिकारिक माध्यम से जांचें।',
    medDesc: 'कुछ संदिग्ध संकेत मिले हैं। किसी भी असत्यापित लिंक को न खोलें। हमेशा बैंक या संस्थान के आधिकारिक ऐप में जाकर जांच करें।',
    lowZeroTitle: 'कम जोखिम (Low Risk)। कोई धोखाधड़ी का संकेत नहीं मिला।',
    lowZeroDesc: 'यह संदेश सामान्य प्रतीत होता है। फिर भी, कभी भी अपना ओटीपी या पासवर्ड किसी को न दें।',
    lowMildTitle: 'कम जोखिम (Low Risk)। केवल सामान्य सूचना के संकेत मिले हैं।',
    lowMildDesc: 'मिले हुए संकेत सामान्य नोटिस जैसे हैं। केवल समय सीमा के शब्दों से संदेश धोखाधड़ी नहीं बनता।',
    safeNextSteps: 'सुरक्षित अगले कदम'
  },
  hinglish: {
    highTitle: 'High Risk Alert! Is message par bilkul act mat karein.',
    highDesc: 'Multiple scam signs mile hain jisse aapka paisa ya bank account chori ho sakta hai. Link mat kholiye, OTP share mat kijiye aur koi payment mat karein.',
    medTitle: 'Medium Risk. Pehle official app se confirm karein.',
    medDesc: 'Kuch suspicious baatein mili hain. Anjaan link par click na karein, direct official bank ya board ki app mein login karke check karein.',
    lowZeroTitle: 'Low Risk. Koi scam warning sign nahi mila.',
    lowZeroDesc: 'Message normal lag raha hai. Par yaad rahe, bank ya koi company kabhi aapse OTP ya PIN nahi maangti.',
    lowMildTitle: 'Low Risk. Sirf basic reminder ke signs mile.',
    lowMildDesc: 'Sirf "today" ya deadline bolne se scam nahi hota. Yeh standard notice ho sakta hai.',
    safeNextSteps: 'Surakshit Next Steps'
  }
};

// Helper utilities
function extractHost(url) {
  return url.replace(/^[a-z]+:\/\//i, '').replace(/^www\./i, '').split(/[\/?#:]/)[0].toLowerCase();
}

function domainMatches(host, officialDomain) {
  return host === officialDomain || host.endsWith('.' + officialDomain);
}

function isOfficialDomain(host) {
  if (/\.(gov|nic|ac|edu)\.in$/.test(host)) return true;
  return Object.values(KNOWN_BRANDS).some(brand =>
    brand.domains.some(dom => domainMatches(host, dom))
  );
}

function detectBrandInHost(host) {
  const parts = host.split(/[.\-_]/);
  for (const brandId in KNOWN_BRANDS) {
    const brand = KNOWN_BRANDS[brandId];
    if (brand.keys.some(k => parts.some(p => p.startsWith(k)))) {
      return brandId;
    }
  }
  return null;
}

function evaluateLinkDetail(host, rawUrl) {
  const reasons = [];
  if (URL_SHORTENERS.has(host)) {
    reasons.push('Shortened link hiding the final destination');
  }
  const brandKey = detectBrandInHost(host);
  if (brandKey) {
    const brand = KNOWN_BRANDS[brandKey];
    if (!brand.domains.some(d => domainMatches(host, d))) {
      reasons.push(`Lookalike impersonating "${brand.name}" on an unofficial domain`);
    }
  }
  const tld = host.split('.').pop();
  if (SUSPICIOUS_TLDS.has(tld)) {
    reasons.push(`Suspicious high-risk web extension (.${tld})`);
  }
  if (/^http:\/\//i.test(rawUrl)) {
    reasons.push('Unencrypted and insecure (http://)');
  }
  if (!reasons.length) {
    reasons.push('Domain is unverified and not in the official registry');
  }
  return `${host}: ${reasons.join(', ')}`;
}

function scanSpans(regex, text, filterFn) {
  const spans = [];
  for (const match of text.matchAll(regex)) {
    if (filterFn && !filterFn(match)) continue;
    spans.push({
      start: match.index,
      end: match.index + match[0].length,
      text: match[0]
    });
  }
  return spans;
}

function evaluateLink(cleanUrl) {
  const host = extractHost(cleanUrl);
  const isOfficial = isOfficialDomain(host);
  const brandKey = detectBrandInHost(host);
  const brand = brandKey ? KNOWN_BRANDS[brandKey] : null;
  const isShortener = URL_SHORTENERS.has(host);
  const tld = host.split('.').pop();
  const isSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
  const isInsecureHttp = /^http:\/\//i.test(cleanUrl);

  let status = 'unverified'; // 'official' | 'fake' | 'suspicious' | 'unverified'
  let label = 'Unverified Third-Party Link';
  let badgeClass = 'warn';
  let brandName = brand ? brand.name : null;
  let officialDomains = brand ? brand.domains : [];

  if (isOfficial) {
    status = 'official';
    label = 'Verified Official Website (Safe / Right)';
    badgeClass = 'safe';
  } else if (brand && !brand.domains.some(d => domainMatches(host, d))) {
    status = 'fake';
    label = `Fake Impostor Link (Mimicking ${brand.name})`;
    badgeClass = 'fake';
  } else if (isShortener) {
    status = 'suspicious';
    label = 'Hidden Shortened Link (High Risk)';
    badgeClass = 'fake';
  } else if (isSuspiciousTld || isInsecureHttp) {
    status = 'suspicious';
    label = 'High-Risk Unsecured Domain';
    badgeClass = 'warn';
  }

  let peoplesAdvice = '';
  if (status === 'official') {
    peoplesAdvice = `Safe to visit. This is the legitimate, verified website of ${brandName || host}.`;
  } else if (status === 'fake') {
    peoplesAdvice = `DO NOT CLICK. This is a fake website pretending to be ${brandName}. The real official website is ${officialDomains.join(' or ')}. Never enter passwords, PINs, or card numbers here.`;
  } else if (status === 'suspicious' && isShortener) {
    peoplesAdvice = `DO NOT CLICK. This link is shortened (${host}) to hide where it really leads. Scammers use this so you cannot see where you are being sent.`;
  } else if (status === 'suspicious') {
    peoplesAdvice = `Caution advised. This website uses an insecure connection or risky domain. Do not submit sensitive details.`;
  } else {
    peoplesAdvice = `Unverified site. This domain is not in the certified brand registry. Confirm with the company before clicking.`;
  }

  return {
    url: cleanUrl,
    host: host,
    status: status,
    label: label,
    badgeClass: badgeClass,
    isOfficial: isOfficial,
    isLookalike: status === 'fake',
    isShortener: isShortener,
    impersonatedBrand: status === 'fake' ? brand : null,
    officialBrand: status === 'official' ? brand : null,
    officialDomains: officialDomains,
    peoplesAdvice: peoplesAdvice,
    detail: evaluateLinkDetail(host, cleanUrl)
  };
}

function scanLinks(text) {
  const good = [];
  const bad = [];
  const allAnalyzed = [];
  for (const match of text.matchAll(URL_REGEX)) {
    const cleanUrl = match[0].replace(/[.,;:!?)\]]+$/, '');
    const start = match.index;
    const end = start + cleanUrl.length;
    const isExplicit = /^(?:https?:\/\/|www\.)/i.test(cleanUrl);
    const charBefore = start > 0 ? text[start - 1] : '';
    if (!isExplicit && charBefore && /[@\w.\/-]/.test(charBefore)) continue;

    const host = extractHost(cleanUrl);
    if (!host.includes('.')) continue;

    const analyzed = evaluateLink(cleanUrl);
    analyzed.start = start;
    analyzed.end = end;
    allAnalyzed.push(analyzed);

    if (analyzed.isOfficial) {
      good.push({ start, end, text: cleanUrl, host, analyzed });
    } else {
      bad.push({ start, end, text: cleanUrl, host, detail: analyzed.detail, analyzed });
    }
  }
  return { good, bad, allAnalyzed };
}

function checkOtpDelivery(text) {
  return /\b(?:otp|one[- ]time password|verification code)\b[^\n]{0,60}?\b\d{4,8}\b|\b\d{4,8}\b[^\n]{0,30}?\b(?:otp|verification code)\b/i.test(text);
}

function scanCredentials(text) {
  const hits = [];
  const isDelivery = checkOtpDelivery(text);
  const hasShareWarning = /\b(?:do not|don'?t|dont|never)\b[^.!?\n]{0,20}\bshare\b/i.test(text);
  const softVerbRegex = new RegExp(`^(?:${SOFT_VERBS})$`, 'i');

  for (const match of text.matchAll(CREDS_REGEX)) {
    const verb = match[1];
    const item = match[2];
    const beforeContext = text.slice(Math.max(0, match.index - 40), match.index);
    if (NEGATION_BEFORE_REGEX.test(beforeContext)) continue;

    const isOtp = /otp|one[- ]time|verification code/i.test(item);
    if (isOtp && isDelivery && (softVerbRegex.test(verb) || hasShareWarning)) {
      // Legitimate OTP delivery message
      continue;
    }
    hits.push({ start: match.index, end: match.index + match[0].length, text: match[0] });
  }

  for (const match of text.matchAll(CREDS_HINGLISH_REGEX)) {
    hits.push({ start: match.index, end: match.index + match[0].length, text: match[0] });
  }

  return { hits, isDelivery };
}

function scanSender(text) {
  const match = /^[ \t]*from:[ \t]*(.+)$/im.exec(text);
  if (!match) return null;

  const line = match[1].trim();
  const emailMatch = /([\w.+-]+)@([\w-]+(?:\.[\w-]+)+)/.exec(line);
  if (!emailMatch) return null;

  const domain = emailMatch[2].toLowerCase();
  const displayName = line.replace(/<[^>]*>/, '').replace(emailMatch[0], '').replace(/["']/g, '').trim();
  const start = match.index + match[0].indexOf(match[1]);
  const end = start + line.length;
  const span = { start, end, text: line };

  // Check if display name claims to be a brand or authority
  const brandClaim = Object.keys(KNOWN_BRANDS).find(id =>
    KNOWN_BRANDS[id].keys.some(key => new RegExp(`\\b${key}`, 'i').test(displayName))
  );

  const claimedOrg = brandClaim ? KNOWN_BRANDS[brandClaim].name : 'an official organisation';

  if (FREE_EMAIL_PROVIDERS.has(domain)) {
    const isImpersonating = brandClaim || /\b(bank|security|support|care|helpdesk|customer|official|admin|hr|payroll|accounts|billing|police|officer|gov|kyc|service)\b/i.test(displayName);
    if (isImpersonating) {
      return {
        bad: Object.assign(span, {
          detail: `Display name claims to be ${claimedOrg}, but the sender uses a free personal account (@${domain})`
        }),
        headerInfo: {
          displayName: displayName || claimedOrg,
          actualEmail: emailMatch[0],
          domain: domain,
          claimedBrand: claimedOrg,
          isSpoofed: true,
          spoofType: 'Free Webmail Impersonation'
        }
      };
    }
    return {
      headerInfo: {
        displayName: displayName || 'Personal Contact',
        actualEmail: emailMatch[0],
        domain: domain,
        claimedBrand: displayName || 'Personal',
        isSpoofed: false
      }
    };
  }

  const hostBrand = detectBrandInHost(domain);
  const targetBrand = brandClaim || hostBrand;

  if (targetBrand) {
    const brand = KNOWN_BRANDS[targetBrand];
    if (brand.domains.some(d => domainMatches(domain, d)) || isOfficialDomain(domain)) {
      return {
        good: { extra: '@' + domain },
        headerInfo: {
          displayName: displayName || brand.name,
          actualEmail: emailMatch[0],
          domain: domain,
          claimedBrand: brand.name,
          isSpoofed: false,
          isVerified: true
        }
      };
    }
    return {
      bad: Object.assign(span, {
        detail: `Claims to be "${brand.name}", but the actual email domain is @${domain} (not official ${brand.domains[0]})`
      }),
      headerInfo: {
        displayName: displayName || brand.name,
        actualEmail: emailMatch[0],
        domain: domain,
        claimedBrand: brand.name,
        isSpoofed: true,
        spoofType: 'Lookalike Phishing Domain'
      }
    };
  }

  return {
    headerInfo: {
      displayName: displayName || 'External Sender',
      actualEmail: emailMatch[0],
      domain: domain,
      claimedBrand: displayName || domain,
      isSpoofed: false
    }
  };
}

function deduplicateStrings(array) {
  return array.filter((value, index) => array.indexOf(value) === index);
}

// Anti-Evasion Homoglyph & Obfuscation Normalizer
const HOMOGLYPHS = {
  '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c', '\u0443': 'y', '\u0456': 'i', '\u0458': 'j', '\u0455': 's',
  '\u03b1': 'a', '\u03bf': 'o', '\u03bd': 'v', '\u03c1': 'p', '\u03c4': 't'
};

function detectAndNormalizeObfuscation(rawText) {
  let normalized = rawText;
  const evasionFlags = [];

  // Check homoglyphs (Cyrillic/Greek character substitution)
  let homoglyphFound = false;
  for (const [badChar, cleanChar] of Object.entries(HOMOGLYPHS)) {
    if (normalized.includes(badChar)) {
      homoglyphFound = true;
      normalized = normalized.split(badChar).join(cleanChar);
    }
  }
  if (homoglyphFound) {
    evasionFlags.push('Deceptive alphabet substitution (Homoglyph Attack) detected and neutralized.');
  }

  // Check obfuscated links like hxxp:// or [dot] / (dot)
  if (/hxxp/i.test(normalized) || /\[dot\]|\(dot\)/i.test(normalized)) {
    normalized = normalized.replace(/hxxp/gi, 'http').replace(/\[dot\]|\(dot\)/gi, '.');
    evasionFlags.push('Obfuscated link syntax (e.g., [dot] or hxxp) normalized.');
  }

  // Remove invisible zero-width spaces
  if (/[\u200B-\u200D\uFEFF]/.test(normalized)) {
    normalized = normalized.replace(/[\u200B-\u200D\uFEFF]/g, '');
    evasionFlags.push('Hidden zero-width characters stripped from message.');
  }

  return { text: normalized, evasionFlags };
}

/**
 * Main Analysis Function
 * Evaluates the message against all 11 rules, computes score, determines risk level,
 * applies false-alarm capping, and prepares highlight spans.
 */
function analyzeMessage(rawInput, customWeights) {
  const weights = Object.assign({}, DEFAULT_POINTS, customWeights || {});
  const isTruncated = rawInput.length > 5000;
  const preProcessed = detectAndNormalizeObfuscation(rawInput);
  const text = preProcessed.text.replace(/\r\n?/g, '\n').slice(0, 5000);
  const evasionFlags = preProcessed.evasionFlags;

  const matchedHits = {};
  const hitDetails = {};
  const safeSignals = [];

  // 1. Scan links
  const links = scanLinks(text);
  if (links.bad.length) {
    matchedHits.link = links.bad;
    hitDetails.link = links.bad.slice(0, 2).map(l => l.detail).join(' | ');
  }
  links.good.forEach(g => {
    if (!safeSignals.some(s => s.id === 'official_link' && s.extra === g.host)) {
      safeSignals.push({ id: 'official_link', extra: g.host });
    }
  });
  const allLinkSpans = links.bad.concat(links.good);

  // 2. Scan Sender
  const senderCheck = scanSender(text);
  if (senderCheck && senderCheck.bad) {
    matchedHits.sender = [senderCheck.bad];
    hitDetails.sender = senderCheck.bad.detail;
  }
  if (senderCheck && senderCheck.good) {
    safeSignals.push({ id: 'official_sender', extra: senderCheck.good.extra });
  }

  // 3. Scan Urgency & Threats (including Indic)
  matchedHits.urgency = scanSpans(URGENCY_REGEX, text).concat(scanSpans(INDIC_URGENCY, text));
  matchedHits.threat = scanSpans(THREAT_REGEX, text).concat(scanSpans(INDIC_THREAT, text));

  // 4. Scan Credentials
  const credsScan = scanCredentials(text);
  matchedHits.creds = credsScan.hits.concat(scanSpans(INDIC_CREDS, text));
  if (credsScan.isDelivery) {
    safeSignals.push({ id: 'otp_delivery', extra: '' });
  }
  if (/\b(?:do not|don'?t|dont|never)\b[^.!?\n]{0,20}\bshare\b/i.test(text)) {
    safeSignals.push({ id: 'warn_share', extra: '' });
  }

  // 5. Scan Money, Rewards, Authority, Secrecy, Callbacks
  matchedHits.money = scanSpans(MONEY_REGEX, text, m => {
    const prev = text.slice(Math.max(0, m.index - 30), m.index);
    return !/\b(?:no|without|zero|nil|not|never)\b[^.!?\n]{0,25}$/i.test(prev);
  });
  matchedHits.reward = scanSpans(REWARD_REGEX, text);
  matchedHits.authority = scanSpans(AUTHORITY_REGEX, text);
  matchedHits.secrecy = scanSpans(SECRECY_REGEX, text);
  matchedHits.callback = scanSpans(CALLBACK_REGEX, text);

  // 6. Scan App Installs / Remote software (excluding URLs already captured)
  matchedHits.install = scanSpans(INSTALL_REGEX, text, m => {
    return !allLinkSpans.some(l => m.index >= l.start && m.index + m[0].length <= l.end);
  });

  // Assemble findings
  const findings = [];
  for (const ruleId of RULE_ORDER) {
    const matches = matchedHits[ruleId];
    if (!matches || !matches.length || !(weights[ruleId] > 0)) continue;

    findings.push({
      id: ruleId,
      name: RULE_METADATA[ruleId].name,
      pts: weights[ruleId],
      hard: HARD_RULES.has(ruleId),
      matches: matches,
      firstPos: Math.min(...matches.map(m => m.start)),
      foundQuotes: deduplicateStrings(matches.map(m => m.text.replace(/\s+/g, ' ').trim())).slice(0, 3),
      detail: hitDetails[ruleId] || '',
      why: RULE_METADATA[ruleId].why
    });
  }

  // Sort findings in the chronological order they appear in the message
  findings.sort((a, b) => a.firstPos - b.firstPos);
  findings.forEach((f, idx) => { f.badgeNumber = idx + 1; });

  // Calculate scores and enforce the False Alarm Guard
  const rawScore = findings.reduce((acc, f) => acc + f.pts, 0);
  let finalScore = Math.min(100, rawScore);
  const hasHardSign = findings.some(f => f.hard);
  let isCapped = false;

  // False Alarm Guard: Without at least 1 Hard Sign, score cannot reach High Risk
  if (!hasHardSign && finalScore >= RISK_THRESHOLDS.highMin) {
    finalScore = RISK_THRESHOLDS.highMin - 1; // 59 max
    isCapped = true;
  }

  let riskLevel = 'low';
  if (finalScore >= RISK_THRESHOLDS.highMin) {
    riskLevel = 'high';
  } else if (finalScore > RISK_THRESHOLDS.lowMax) {
    riskLevel = 'medium';
  }

  // Prepare non-overlapping highlight marks for the text
  const markList = [];
  findings.forEach(f => {
    f.matches.forEach(m => {
      markList.push({
        start: m.start,
        end: m.end,
        badgeNumber: f.badgeNumber,
        ruleId: f.id,
        hard: f.hard
      });
    });
  });

  markList.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const cleanMarks = [];
  let lastEnd = 0;
  for (const mark of markList) {
    if (mark.start < lastEnd) continue;
    cleanMarks.push(mark);
    lastEnd = mark.end;
  }

  // Direct single URL testing support (when the message is essentially a link being tested)
  const trimmedInput = rawInput.trim();
  const cleanInput = trimmedInput.replace(/^https?:\/\//i, '').replace(/^www\./i, '').replace(/\/+$/, '').toLowerCase();
  const directLink = links.allAnalyzed.find(l => {
    const cleanUrl = l.url.replace(/^https?:\/\//i, '').replace(/^www\./i, '').replace(/\/+$/, '').toLowerCase();
    return cleanInput === cleanUrl || cleanInput === l.host.toLowerCase();
  });

  if (directLink && trimmedInput.split(/\s+/).length <= 2) {
    if (directLink.status === 'fake') {
      finalScore = 80;
      riskLevel = 'high';
    } else if (directLink.status === 'official') {
      finalScore = 0;
      riskLevel = 'low';
    } else if (directLink.status === 'suspicious') {
      finalScore = directLink.isShortener ? 45 : 55;
      riskLevel = 'medium';
    } else {
      finalScore = 25;
      riskLevel = 'low';
    }
  }

  return {
    originalText: text,
    isTruncated,
    findings,
    safeSignals,
    rawScore,
    finalScore,
    isCapped,
    hasHardSign,
    riskLevel,
    cleanMarks,
    emailHeader: senderCheck ? senderCheck.headerInfo : null,
    evasionFlags: evasionFlags || [],
    links: links.allAnalyzed || []
  };
}

// Preset library of realistic fictional messages for testing
const SAMPLE_MESSAGES = [
  {
    id: 'sbi-kyc',
    group: 'scams',
    title: 'SBI KYC Alert',
    badge: 'SMS Phishing',
    expected: 'high',
    text: 'SBI ALERT: Your KYC is incomplete and your account will be blocked today. Update immediately at http://sbi-kyc-update.example/verify and share the OTP you receive to confirm.',
    notes: 'The textbook bank scam: creates panic urgency, threatens account freeze, provides a fake domain, and steals your OTP.'
  },
  {
    id: 'fake-url-check',
    group: 'scams',
    title: 'Fake SBI Link (URL Test)',
    badge: 'Fake Link',
    expected: 'high',
    text: 'http://sbi-kyc-update.com/login',
    notes: 'URL Inspector Test: Demonstrates instant detection of an unauthorized lookalike domain pretending to be State Bank of India.'
  },
  {
    id: 'fake-gmail-security',
    group: 'scams',
    title: 'Fake Gmail Security Alert',
    badge: 'Email Phishing',
    expected: 'high',
    text: 'From: Google Security <security-alerts@gmail-auth-service.example>\nSubject: Critical security alert: unauthorized sign-in detected\n\nDear Gmail user,\n\nSomeone in Russia attempted to log into your Gmail account. Your access will be deactivated within 24 hours. Verify your Google password immediately to secure your mailbox: http://gmail-security-login.example/auth\n\nGoogle Accounts Team',
    notes: 'Spoofs Google Security with a lookalike domain and asks you to enter your password on an unofficial site.'
  },
  {
    id: 'fake-gmail-freemail',
    group: 'scams',
    title: 'HDFC Alert from @gmail.com',
    badge: 'Free Email Impersonation',
    expected: 'high',
    text: 'From: HDFC Bank Helpdesk <hdfc.customer.support.india@gmail.com>\nSubject: Urgent: Verify PAN Card to avoid account deactivation\n\nDear customer,\nYour net banking service will be suspended tonight due to pending PAN card verification. Submit your card number, CVV and login details at http://hdfc-pan-portal.example/update to restore service.',
    notes: 'A free @gmail.com address claiming to be HDFC Bank, accompanied by netbanking & CVV credential harvesting.'
  },
  {
    id: 'digital-arrest',
    group: 'scams',
    title: 'Digital Arrest Threat',
    badge: 'Police / CBI Impersonation',
    expected: 'high',
    text: 'This is Inspector Rao from the Cyber Crime Branch. A parcel in your name contains illegal narcotics and your Aadhaar is linked to a money laundering case. Stay on the video call and do not tell your family. Transfer ₹85,000 to the government verification account today to avoid arrest.',
    notes: 'Extreme extortion: fake police threats, psychological isolation ("do not tell family"), and demanding money transfers.'
  },
  {
    id: 'courier-parcel',
    group: 'scams',
    title: 'India Post Redelivery Fee',
    badge: 'Parcel Delivery Scam',
    expected: 'high',
    text: 'India Post: Your parcel could not be delivered because the address is incomplete. Pay a ₹49 redelivery fee within 24 hours at http://indiapost-redelivery.example/pay or the parcel will be returned.',
    notes: 'Small fees (₹49) lure people into typing credit card / debit card details into phishing portals.'
  },
  {
    id: 'wfh-job-scam',
    group: 'scams',
    title: 'Work From Home Job Offer',
    badge: 'Employment Fraud',
    expected: 'high',
    text: 'Congratulations! You are selected for a part-time job. Earn ₹5,000 per day working from home liking videos. Pay a ₹999 registration fee to confirm your seat. Only 10 slots left, confirm today on WhatsApp.',
    notes: 'Standard Telegram/WhatsApp employment scam demanding an upfront "registration fee".'
  },
  {
    id: 'electricity-bill',
    group: 'scams',
    title: 'Electricity Disconnection',
    badge: 'Utility Bill Threat',
    expected: 'high',
    text: 'Dear consumer, your electricity power supply will be disconnected tonight at 9:30 PM because your bill payment was not updated. Call our officer immediately on 9876543210 or install the support app at http://power-board.example/app.apk',
    notes: 'Urgent threat to shut down electricity, coupled with APK malware download and private callback numbers.'
  },
  {
    id: 'genuine-sbi-otp',
    group: 'genuine',
    title: 'Genuine SBI OTP Delivery',
    badge: 'Safe Bank SMS',
    expected: 'low',
    text: '482913 is your OTP for transaction of Rs 2,500.00 at AMAZON INDIA. Valid for 10 mins. Do not share this OTP with anyone, including bank staff. SBI will never ask for your OTP. - SBI',
    notes: 'Genuine notification: Delivers an OTP you requested, gives explicit safety warning never to share it, and makes no demands.'
  },
  {
    id: 'genuine-college-notice',
    group: 'genuine',
    title: 'College Exam Fee Notice',
    badge: 'Safe Campus Notice',
    expected: 'low',
    text: 'Reminder: The last date to submit the semester exam fee is today by 5:00 PM. Pay at the accounts office or through the verified student portal: https://erp.university.edu.in/fees. Never share your passwords with anyone.',
    notes: 'Shows false-alarm prevention: Mentions "today" and "fee", but points to official .edu.in domain and issues security advice.'
  },
  {
    id: 'genuine-amazon-order',
    group: 'genuine',
    title: 'Amazon Delivery Update',
    badge: 'Safe Order Update',
    expected: 'low',
    text: 'Your Amazon order #407-1234567 has been dispatched and will arrive by tomorrow. Track your package live in the Amazon App or at https://www.amazon.in/your-orders.',
    notes: 'Routine legitimate communication linking directly to verified official amazon.in domain.'
  },
  {
    id: 'official-sbi-check',
    group: 'genuine',
    title: 'Official SBI Portal (URL Test)',
    badge: 'Verified Official',
    expected: 'low',
    text: 'https://onlinesbi.sbi',
    notes: 'URL Inspector Test: Demonstrates instant validation of an official, certified banking domain (0/100 Safe).'
  }
];

// Evaluation Corpus for Self-Testing
const TEST_CORPUS = [
  { group: 'Bank Scams', expect: 'high', text: 'HDFC Bank: Your account is suspended due to incomplete KYC. Click https://hdfc-secure-kyc.example/update and enter your net banking password to reactivate.' },
  { group: 'Bank Scams', expect: 'high', text: 'Dear customer, your debit card will be blocked within 2 hours. Call our officer now and give your card number and CVV to stop the block.' },
  { group: 'Bank Scams', expect: 'high', text: 'ICICI: Rs 49,999 debited from your account. If not you, share the OTP sent to your phone with our agent to cancel the transaction immediately.' },
  { group: 'Bank Scams', expect: 'high', text: 'Your PAN is not linked with your bank account. Account will be frozen today. Update at bit.ly/3xKycNow and submit your Aadhaar number.' },
  { group: 'UPI Scams', expect: 'high', text: 'You have received a collect request of Rs 1. Approve it and enter your UPI PIN to receive your refund of Rs 3,200.' },
  { group: 'UPI Scams', expect: 'high', text: 'Paytm KYC expired. Your wallet will be closed today. Scan this QR and pay Rs 10 to verify your identity.' },
  { group: 'Email Scams', expect: 'high', text: 'From: Gmail Support <gmail.support.team@gmail.com>\nSubject: Your mailbox is full\n\nYour mailbox will be disabled in 24 hours. Verify your password immediately at http://mail-quota-fix.example/login' },
  { group: 'Email Scams', expect: 'high', text: 'From: Microsoft Account Team <security@microsoft-alerts.example>\nSubject: Unusual sign-in activity\n\nWe detected a sign-in from Russia. Confirm your password now at http://ms-account-verify.example or your account will be locked.' },
  { group: 'Delivery Scams', expect: 'high', text: 'DTDC: Your package is held at customs. Pay a clearance fee of Rs 85 at http://dtdc-clearance.example/pay within 24 hours or it will be returned.' },
  { group: 'Delivery Scams', expect: 'high', text: 'Delhivery: Delivery attempt failed. Update your address and pay Rs 29 re-delivery charge: https://tinyurl.com/delhiv-redeliver' },
  { group: 'Police Scams', expect: 'high', text: 'This is the Narcotics Control Bureau. A parcel under your Aadhaar contains MDMA. A case is registered. Do not disconnect the call and do not tell anyone. Move your savings to the RBI safe account to avoid arrest.' },
  { group: 'Police Scams', expect: 'high', text: 'I am calling from TRAI. Your mobile number will be disconnected in 2 hours for illegal advertisements. Press 9 and install AnyDesk so our officer can verify your SIM.' },
  { group: 'Job Scams', expect: 'high', text: 'Work from home! Earn Rs 3,000 per day liking videos. Pay Rs 1,200 registration fee to start. Limited slots, join today on WhatsApp.' },
  { group: 'Job Scams', expect: 'high', text: 'Instant loan up to Rs 5 lakh with no documents. Pay Rs 2,000 processing fee first. Offer ends today. Apply: http://quick-cash-loan.example/apply' },
  { group: 'Genuine Banking', expect: 'low', text: 'Rs 1,250.00 debited from A/c XX4821 on 12-10-26 to VPA grocer@okaxis (UPI Ref 628419375). If not done by you, call 1800-1234 or visit your branch. - SBI' },
  { group: 'Genuine Banking', expect: 'low', text: 'Your HDFC Bank credit card statement for Sept is ready. Total due Rs 4,310 by 05-Nov. View it in the HDFC Bank MobileBanking app. Never share your OTP or CVV with anyone.' },
  { group: 'Genuine Banking', expect: 'low', text: '591204 is the OTP to log in to your ICICI Bank account. Valid for 5 minutes. Do not share it with anyone, including bank staff.' },
  { group: 'Genuine Delivery', expect: 'low', text: 'Your Flipkart order for boAt Earbuds is shipped and will arrive by Thursday. Track here: https://www.flipkart.com/orders' },
  { group: 'Genuine Delivery', expect: 'low', text: 'Delhivery: Your package from Myntra is out for delivery today. Share OTP 4417 with the delivery partner only at your door. Do not share it in advance.' },
  { group: 'Genuine College', expect: 'low', text: 'All II-year CSE students: Internal Test 2 will be held on 13 Nov in Room 204. Lab records must be submitted to the department office by 12 noon the same day.' },
  { group: 'Genuine College', expect: 'low', text: 'Placement drive: TCS visits our campus on 20 Nov. Register on the placement portal by Friday. There is no registration fee. Carry your resume and ID card.' },
  { group: 'Genuine Email', expect: 'low', text: 'From: Google <no-reply@accounts.google.com>\nSubject: Security alert\n\nA new sign-in on Windows. If this was you, you can ignore this email. If not, we will help you secure your account at https://myaccount.google.com/security' },
  { group: 'Unclear / Verify', expect: 'medium', text: 'Your electricity bill of Rs 1,840 is due. Pay by 25 Nov to avoid disconnection: https://billdesk-power.example/pay' },
  { group: 'Unclear / Verify', expect: 'medium', text: 'Final reminder: your Jio recharge expires today. Recharge now at http://jio-recharge-offers.example to keep your number active.' }
];

// Export for browser or testing
if (typeof module !== 'undefined') {
  module.exports = {
    DEFAULT_POINTS,
    RULE_ORDER,
    HARD_RULES,
    RISK_THRESHOLDS,
    KNOWN_BRANDS,
    RULE_METADATA,
    SAFE_SIGNALS,
    analyzeMessage,
    evaluateLink,
    SAMPLE_MESSAGES,
    TEST_CORPUS,
    UI_TRANSLATIONS
  };
}
