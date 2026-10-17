# Scam Spotter 🛡️
> **SETU 2026 Forge Realm • Problem Statement PS-01**  
> *Paste a suspicious message. See the warning signs, the risk level, and what to do next.*

Scam Spotter is a transparent, explainable, rule-based web application designed to protect students, parents, and everyday citizens against cyber fraud, phishing emails (fake Gmail alerts), KYC SMS traps, delivery scams, and "digital arrest" extortion.

---

## 🌟 Key Highlights & Challenge Solutions

1. **Deterministic Rule Engine (No Black-Box AI Guesses)**
   - Operates on **11 explicit, explainable detection rules** with visible point weights.
   - Every detected red flag displays: **Warning Sign**, **Found Quote**, **Why It Matters**, and **Point Weight**.

2. **Fake Gmail & Email Impersonation Detection**
   - Detects free email services (`@gmail.com`, `@yahoo.com`) pretending to be banks or tech support (e.g., `From: HDFC Bank <hdfc.help@gmail.com>`).
   - Spots domain lookalikes spoofing Google Security or Microsoft Account teams (`security@gmail-auth-service.example`).

3. **In-Message Highlight Synchronization**
   - Highlights warning phrases directly within the original message using numbered badges.
   - Clicking any finding smoothly scrolls to and highlights the exact sentence in the text.

4. **False-Alarm Guard**
   - Distinguishes **Hard Signs** (active pathways to theft: lookalike links, OTP demands, fake senders) from **Soft Signs** (urgency words, deadlines).
   - Soft signs alone are strictly capped below High Risk (<60), ensuring legitimate notifications (like college fee deadlines or utility reminders) are never falsely branded as scams.
   - Detects legitimate safe signals (official `.gov.in`, `.edu.in`, bank domains, and standard "never share OTP" disclaimers).

5. **100% Client-Side Privacy**
   - All evaluation runs locally in the user's browser.
   - Sensitive personal messages, phone numbers, or account details are **never transmitted** to external servers.

6. **Actionable Emergency Guidance & WhatsApp Alert Generator**
   - **Safe Next Steps**: Clear, prioritized recommendations for what to do and what NOT to do.
   - **Emergency Panic Playbook**: Immediate steps if a user already shared an OTP, clicked a link, or sent money.
   - **WhatsApp Family Alert**: 1-click formatted warning message ready to paste into family WhatsApp groups without forwarding malicious links.
   - **Helpline 1930 & cybercrime.gov.in**: Direct official contact integration for India.

7. **Interactive Features for Community Awareness**
   - **Multi-Language Rationale (English / हिन्दी / Hinglish)**: Instant language switch for verdict headlines and safe steps.
   - **Email Header Identity Inspector**: Exposes display name spoofing vs actual envelope sender domains.
   - **Screenshot OCR Text Extractor**: Upload or drop screenshots to extract text directly into the inspector.
   - **Formal Cyber Incident Report Generator**: 1-click generation of formatted incident summaries with legal IPC/IT Act references for police and bank complaints.
   - **Rulebook Tuner**: Users and evaluators can customize rule point weights and see scores update live.
   - **Spot the Scam (Quiz)**: Interactive 10-question challenge for freshers' orientations and family cyber-awareness sessions.
   - **Live Test Suite**: 24 automated test cases with 100% accuracy validation and 1-click loading into the inspector.


---

## 📊 Judging Criteria Alignment

| Criterion | Max Marks | Implementation Highlights |
| :--- | :---: | :--- |
| **Monetization & Sustainability** | **30** | Detailed 4-pillar revenue model: Free family tier + ₹49/mo Family Guardian, ₹15/student/yr College Campus Safety License, ₹0.20/call B2B Bank/Courier Verification API, and Telecom/Cyber Cell CSR grants. Near-zero compute cost via client-side architecture. |
| **Innovation** | **20** | Dual Hard/Soft sign classification with False Alarm capping, bidirectional click-to-highlight synchronization, fake Gmail header inspection, Indic language support (Hindi/Hinglish), and 1-click WhatsApp family warning generator. |
| **UI/UX** | **15** | Mobile-responsive layout, high-contrast typography, accessible color coding (Low = Green, Medium = Amber, High = Red), interactive risk gauge, instant sample scenario chips, and dark/light mode toggle. |
| **Completeness** | **35** | End-to-end functionality, comprehensive error handling for empty/short/junk input, 24-case automated test suite with 100% pass rate, and full coverage of the problem statement. |

---

## 🚀 How to Run Locally

Because the project is built with vanilla HTML5, CSS3, and modern JavaScript, no build step or node installation is mandatory for users:

1. Double-click or open `index.html` in any modern web browser (Chrome, Edge, Safari, Firefox).
2. Alternatively, serve with any local HTTP server:
   ```bash
   npx serve .
   ```
   or
   ```bash
   python -m http.server 3000
   ```

---

## 📁 File Structure

```text
├── index.html        # Accessible semantic structure, tabs, and layout
├── styles.css        # Modern design system, responsive grid, theme variables
├── rules.js          # Core 11 detection rules, brand registry, false-alarm logic
├── app.js            # UI controller, event bindings, quiz game, test runner
└── README.md         # Documentation & judging criteria breakdown
```
