# CSE 543: Information Assurance & Security - Exam Study Guide

**Coverage:** This guide includes material from PDFs 1-4. You'll need to create a new chat for: Risk Analysis, CVSS v4.0, LLM Security, and CTF Education.

---

## 1. CURRENT CYBERATTACK/INCIDENT TRENDS (2024)

### IC3 2023 Report Key Statistics
- **Total Losses:** $12.5 billion
- **Complaints Filed:** 880,418
- **Top Attack Vector:** Phishing/Vishing/Smishing (298,878 complaints)
- **Age Group with Highest Losses:** 60+ ($4.8 billion)
- **New Ransomware Variants:** 67 in 2024

### Major 2024 Incidents
1. **National Public Data Breach**
   - 2.9 billion records exposed
   - Social Security numbers, addresses, phone numbers
   
2. **Bybit Cryptocurrency Hack**
   - $1.5 billion stolen via Lazarus Group
   
3. **Yes24 Ransomware Attack**
   - Korean e-commerce platform
   - Customer data compromised
   
4. **UNFI Ransomware Attack**
   - Major food distributor
   - Supply chain disruption

---

## 2. FOUR CATEGORIES OF THREATS & PROTECTION

### The Four Threat Categories

**1. DISCLOSURE (Confidentiality Violation)**
- **Definition:** Unauthorized access to sensitive information
- **Examples:** Data breaches, eavesdropping, social engineering
- **Protection:** Encryption, access controls, data classification

**2. DECEPTION (Integrity Violation)**
- **Definition:** False data accepted as genuine
- **Examples:** Malware, man-in-the-middle attacks, spoofing
- **Protection:** Digital signatures, checksums, input validation

**3. DISRUPTION (Availability Violation)**
- **Definition:** Prevention of legitimate access to resources
- **Examples:** DoS/DDoS attacks, ransomware, system failures
- **Protection:** Redundancy, backups, DDoS mitigation, disaster recovery

**4. USURPATION (Integrity/Availability Violation)**
- **Definition:** Unauthorized control of system resources
- **Examples:** Account takeover, privilege escalation, botnet control
- **Protection:** Strong authentication, least privilege, monitoring

---

## 3. CIA TRIAD + AUTHENTICITY & NON-REPUDIATION

### Core Principles
- **Confidentiality:** Only authorized parties can access information
- **Integrity:** Information remains accurate and unaltered
- **Availability:** Systems and data are accessible when needed

### Additional Principles
- **Authenticity:** Verification that parties are who they claim to be
- **Non-repudiation:** Cannot deny having performed an action

### Real-World Mapping Examples
- **Stuxnet:** Integrity violation (falsified sensor readings while manipulating centrifuges)
- **Ransomware:** Availability violation (encrypts data, prevents access)
- **Data Breach:** Confidentiality violation (unauthorized access to personal data)

---

## 4. CATEGORIES OF SECURITY CONTROLS

### By Function (What They Do)
1. **Preventive:** Stop incidents before they occur (firewalls, encryption)
2. **Detective:** Identify incidents during/after occurrence (IDS, logs)
3. **Corrective:** Fix damage after incident (patches, backups)
4. **Deterrent:** Discourage attacks (warning banners, security cameras)
5. **Recovery:** Restore systems after incident (disaster recovery plans)
6. **Compensating:** Alternative controls when primary fails

### By Type (How They're Implemented)
1. **Administrative:** Policies, procedures, training
2. **Technical:** Software/hardware solutions (firewalls, encryption)
3. **Physical:** Locks, guards, surveillance cameras

### Control Matrix
| Function | Administrative | Technical | Physical |
|----------|---------------|-----------|----------|
| Preventive | Security policies | Firewalls | Door locks |
| Detective | Background checks | IDS | CCTV |
| Corrective | Disciplinary actions | Patches | Facility repairs |

---

## 5. ADMINISTRATIVE CONTROLS IN DETAIL

### Key Characteristics
- **Foundation of security:** Must exist before technical/physical controls
- **Most critical but often overlooked**
- **Examples:** Policies, procedures, hiring practices, training

### Important Administrative Controls
1. **Security Policies:** Define acceptable/unacceptable behavior
2. **Separation of Duties:** No single person controls entire process
3. **Mandatory Vacation:** Forces job rotation, helps detect fraud
4. **Background Checks:** Verify employee trustworthiness
5. **Security Awareness Training:** Educate users on threats
6. **Incident Response Plans:** Define actions during security events

### Why Administrative Controls Matter
- Technical controls without policies = ineffective
- Example: Firewall without policy on what to block = useless
- Human factor is often the weakest link

---

## 6. CHALLENGES WITH AUDITING SYSTEMS

### Key Challenges
1. **Volume of Logs:** Too much data to analyze manually
2. **False Positives:** Legitimate activity flagged as suspicious
3. **Storage Requirements:** Logs consume significant disk space
4. **Performance Impact:** Logging can slow systems
5. **Privacy Concerns:** Logs may contain sensitive information
6. **Skill Requirements:** Need trained personnel to interpret logs

### Logging vs. Auditing
- **Logging:** Recording events as they happen (automated)
- **Auditing:** Reviewing and analyzing logs (manual/automated analysis)

### Three-Phase Audit Process
1. **Planning:** Define scope, objectives, resources
2. **Execution:** Collect evidence, test controls
3. **Reporting:** Document findings, recommendations

### Best Practices
- Centralized log management
- Automated analysis tools (SIEM)
- Regular log reviews
- Secure log storage (prevent tampering)
- Clear retention policies

---

## 7. AUTHENTICATION & ACCESS CONTROL

### What is Authentication?
Authentication validates a user's identity. Authorization grants permissions after authentication.

### Four Authentication Factors
1. **What you have:** Badge, ID card, security token
2. **What you know:** Password, PIN, secret information
3. **Who you are:** Biometrics (fingerprint, face, iris)
4. **Where you are:** Location (in front of specific terminal)

---

## 8. PASSWORDS

### Password Storage Methods
- Plain text files (NEVER use)
- Encrypted files
- **One-way hashes with salt** (recommended)
  - Salt = random number added to password before hashing
  - Prevents rainbow table attacks

### Password Vulnerabilities
1. **Dictionary Attack:** Try common words/phrases
2. **Brute-Force Attack:** Try all possible combinations
3. **Credential Stuffing:** Use leaked credentials from other breaches
4. **Phishing:** Trick users into revealing passwords
5. **Keylogger:** Record keystrokes
6. **Rainbow Table Attack:** Pre-computed hash lookups

### Password Countermeasures
1. **Random Selection:** Use password generators
2. **Strong Passwords:** Length + complexity
3. **Account Lockout Policy:** Disable after N failed attempts
4. **Multi-Factor Authentication (MFA)**
5. **Password Salting and Hashing**
6. **CAPTCHA Implementation**
7. **Password Expiration and Rotation** (debated)
8. **Limit Password Reuse**
9. **Monitor for Suspicious Login Activity**

### NIST Password Guidelines (Updated)
- **Do NOT require:** Character composition rules, mandatory periodic changes
- **Should force change:** Only if evidence of compromise

---

## 9. ONE-TIME PASSWORDS (OTP)

### Three OTP Generation Methods

**1. Time-Synchronization (TOTP)**
- Uses synchronized time between client and server
- Formula: f(tx) = px where tx = current time
- Example: Google Authenticator
- Passwords: p1, p2, ..., px

**2. Challenge-Response**
- Server sends unique challenge
- Formula: f(ci) = pi where ci = challenge from server
- Passwords in order: p1, p2, ..., pi, ...pn

**3. Hash Chain**
- Uses sequence of hash functions
- Formula: h(s) = p1, h(p1) = p2, ..., h(pn-1) = pn
- Passwords used in **reverse order:** pn, pn-1, ..., p2, p1
- s = initial seed, h = hash function

---

## 10. BIOMETRIC AUTHENTICATION

### Types of Biometrics
- **Physiological:** Fingerprints, iris, retina, face, DNA
- **Behavioral:** Voice, keystroke dynamics, signature

### Key Metrics for Measuring Effectiveness

**1. False Reject Rate (FRR) - Type I Error**
- Rate at which legitimate users are incorrectly denied
- Formula: (Rejected Legitimate Users / Total Legitimate Attempts) × 100
- Example: 5 out of 100 legitimate users rejected = 5% FRR
- **High FRR = User frustration**

**2. False Accept Rate (FAR) - Type II Error**
- Rate at which unauthorized users are incorrectly accepted
- Formula: (Accepted Unauthorized Users / Total Unauthorized Attempts) × 100
- Example: 3 out of 100 unauthorized users accepted = 3% FAR
- **High FAR = Security risk**

**3. Crossover Error Rate (CER) / Equal Error Rate (EER)**
- Point where FRR = FAR
- Lower CER = More accurate system
- Example: CER of 2% means 2/100 attempts result in error
- **Key metric for comparing biometric systems**

### Balancing FAR and FRR

**Trade-off Principle:**
- Improving security (lowering FAR) → increases FRR (user inconvenience)
- Improving usability (lowering FRR) → increases FAR (security risk)

**Tuning by Use Case:**
- **High-Security (Military, Banking):** FAR ↓, accept higher FRR
- **High-Usability (Consumer devices):** FRR ↓, accept higher FAR

### Biometric Rankings (Effectiveness & Acceptance)

| Biometric | Universality | Uniqueness | Permanence | Collectability | Performance | Acceptability | Circumvention |
|-----------|-------------|-----------|------------|----------------|-------------|---------------|---------------|
| Face | H | L | M | H | L | H | L |
| Fingerprint | M | H | H | M | H | M | H |
| Iris | H | H | H | M | H | L | H |
| Retina | H | H | M | L | H | L | H |
| DNA | H | H | H | L | H | L | L |
| Keystroke | L | L | L | M | L | M | M |
| Voice | M | L | L | M | L | H | L |
| Signature | L | L | L | H | L | H | L |

H=High, M=Medium, L=Low

---

## 11. AUTHENTICATION VULNERABILITIES & RECENT ATTACKS

### Recent Authentication Attacks (2022-2023)

**1. Microsoft Azure AD Token Forgery (2023)**
- **Attack Surface:** Token validation/issuance in Azure AD
- **Method:** Forged security tokens to bypass authentication
- **Weakness:** Inadequate token signature validation, over-reliance on tokens
- **Impact:** Unauthorized email access for multiple organizations

**2. MGM Resorts & Caesars Entertainment (2023)**
- **Attack Surface:** Employee credentials via social engineering
- **Method:** Manipulated help desk to divulge login credentials
- **Weakness:** Inadequate employee training, flawed help desk procedures
- **Impact:** Major operational disruption

**3. Cisco VPN Zero-Day Vulnerability (2023)**
- **Attack Surface:** VPN authentication mechanism
- **Method:** Zero-day exploit allowed unauthorized VPN sessions
- **Weakness:** Failure to validate authentication requests, exposed services
- **Impact:** Unauthorized remote access to corporate networks

**4. LastPass Data Breach (2022-2023)**
- **Attack Surface:** Developer's compromised home computer
- **Method:** Exploited third-party software vulnerability to access password vaults
- **Weakness:** Insufficient endpoint security, lack of access controls/network segmentation
- **Impact:** Encrypted password vaults compromised

**5. Twilio & Cloudflare Phishing (2022)**
- **Attack Surface:** Employee credentials and MFA tokens via phishing
- **Method:** Fake login portals harvested credentials and OTP codes
- **Weakness:** Employee susceptibility to phishing, non-phishing-resistant MFA (SMS/OTP)
- **Impact:** Temporary account compromise

### Key Observations on Authentication Vulnerabilities

**1. Human Factors:** Social engineering and phishing remain highly effective
**2. Authentication Mechanisms:** Weak MFA implementations, token validation flaws
**3. Software Vulnerabilities:** Unpatched systems, zero-day exploits
**4. Insufficient Security Protocols:** Lack of employee training, weak endpoint protection

---

## 12. HOW TO REDUCE AUTHENTICATION ATTACK SURFACE

### Key Mitigation Strategies

1. **Enhance Employee Training**
   - Regular phishing awareness training
   - Social engineering detection
   - Secure credential management

2. **Implement Stronger MFA**
   - Use FIDO2 (see next section)
   - Avoid SMS-based OTP (susceptible to phishing)
   - Hardware tokens preferred

3. **Regularly Patch and Update Systems**
   - Automated patch management
   - Vulnerability scanning
   - Zero-day mitigation strategies

4. **Strengthen Authentication Processes**
   - Token binding
   - Proper validation mechanisms
   - Continuous monitoring

5. **Reduce Exposure of Critical Services**
   - Network segmentation
   - Least privilege access
   - Zero trust architecture

6. **Conduct Regular Security Audits**
   - Penetration testing
   - Access reviews
   - Vulnerability assessments

---

## 13. FIDO2 (FAST IDENTITY ONLINE)

### What is FIDO2?
Open authentication standard by FIDO Alliance and W3C for **passwordless login** using public key infrastructure (PKI) or built-in biometrics.

### Key Features

**1. Eliminates Passwords**
- Uses built-in device features: fingerprint, face recognition, PIN
- No password to remember, steal, or phish

**2. Private Keys Stay on Device (Decentralized)**
- **Client:** Stores private key locally
- **Server (Relying Party):** Stores only public key
- **Benefits:** Resistant to impersonation, social engineering, man-in-the-middle attacks

**3. Examples**
- Windows Hello, YubiKey, Apple Passkeys

### FIDO2 Specification Protocols

**CTAP (Client to Authenticator Protocol)**
- Communication between external authenticator (USB/NFC device) and client device
- Examples: YubiKey, security keys

**WebAuthn (Web Authentication API)**
- Communication between browser and Relying Party (RP)
- Standard API for web-based authentication

### FIDO2 Authentication Process

**A. Registration Phase**
1. RP sends challenge to client
2. Client/Authenticator generates public/private key pair
3. Public key sent to RP for storage

**B. Authentication Phase**
1. RP sends challenge to client
2. Authenticator verifies user (biometric/PIN)
3. Authenticator signs challenge with private key
4. Signed challenge returned to RP
5. RP verifies signature using stored public key

### Why FIDO2 is Secure
- **Phishing-resistant:** Private key never leaves device
- **No shared secrets:** Each site gets unique key pair
- **No password database:** Nothing for attackers to steal from server
- **Replay attack resistant:** Challenges are unique

---

## 14. SINGLE SIGN-ON (SSO)

### What is SSO?
Allows users to access multiple applications using a single set of login credentials (token) without repeated logins.

### SSO Components

**Identity Provider (IdP)**
- Authenticates users and stores identities
- Examples: Google, Azure AD (Microsoft Entra ID), Facebook, Apple, Okta

**Service Provider (SP)**
- Applications/services that rely on IdP for authentication
- Trust relationship with IdP

**Token**
- Digital credential issued by IdP after authentication
- Shared with SPs to prove identity

### SSO Flow (Typical Process)

1. User browses to SP (domain1.com)
2. SP redirects to IdP (Auth Server)
3. User logs in at IdP, or cookie is available
4. IdP sends token and redirects back to SP
5. SP stores cookie for domain1
6. User uses token to authenticate at SP
7. Later, user browses to different SP (domain2.com)
8. SP redirects to IdP
9. IdP recognizes user (cookie available)
10. IdP sends token without requiring re-login
11. SP stores cookie for domain2
12. User authenticated at second SP seamlessly

### SSO Protocols

**SAML (Security Assertion Markup Language)**
- XML-based protocol
- Exchanges authentication/authorization data between IdP and SP
- Common in enterprise environments

**OAuth 2.0**
- **Authorization** framework (not primarily authentication)
- Grants secure access to resources
- Used by social logins (Google, Facebook)

**OpenID Connect (OIDC)**
- Adds identity layer to OAuth 2.0
- For federated identity management
- Uses JWT ID token with user profile information

### SAML Token Components
- **Issuer:** IdP that issued the assertion
- **Subject:** Authenticated user identity
- **Conditions:** Time constraints on validity (NotBefore, NotOnOrAfter)
- **AuthnStatement:** When and how user was authenticated
- **AttributeStatement:** Additional user info (name, email, etc.)

### SSO Features
1. **Centralized Authentication:** Single IdP authenticates for all SPs
2. **Session Management:** Session shared across participating services
3. **Security:** Uses secure protocols (SAML, OAuth, OIDC)

### Common IdPs

| IdP | Token Format | Protocols | Primary Use Case |
|-----|-------------|-----------|------------------|
| Google | JWT | OAuth2, OIDC, SAML | SSO for Google & 3rd party apps |
| Azure AD | JWT/SAML | SAML, OIDC, OAuth2 | Enterprise SSO & Microsoft ecosystem |
| Facebook | Access Token | OAuth2 | Social login for public apps |
| Apple | ID Token | OAuth2 + OIDC | Privacy-first login for Apple users |
| Okta | JWT/SAML | SAML, OIDC, OAuth2 | Enterprise IAM & federated SSO |

---

## 15. SECURITY STRATEGIES OVERVIEW

### What is a Cybersecurity Strategy?
A comprehensive, high-level plan focusing on long-term goals with a structured, proactive approach to protecting digital assets.

**Strategy vs Plan vs Policy vs Framework:**
- **Strategy:** Overarching direction and goals (the "what" and "why")
- **Plan:** Specific steps to be taken (the "how")
- **Policy:** Rules and guidelines (the "must" and "must not")
- **Framework:** Set of best practices/standards (the "recommended approach")

### Why Strategy Matters
1. Managing diverse and evolving threats
2. Cost efficiency and reducing financial losses
3. Ensuring business continuity and resilience
4. Balancing security with functionality
5. Adapting to changing cyber landscape
6. Maintaining trust and compliance

### Key Components of Cybersecurity Strategy
1. Threat modeling and risk assessment
2. Security policies and procedures
3. Threat prevention measures
4. Detection and monitoring
5. Incident response plan
6. Recovery and continuity planning
7. Compliance and legal considerations
8. Training and awareness
9. Third-party risk management
10. Adaptation to new threats

### Real-World Case Studies

**Target Data Breach (2013)**
- **Issue:** Third-party vendor compromise
- **Impact:** $236 million, 40M credit cards, 70M customer records
- **Lesson:** Need vendor security requirements, network segmentation

**WannaCry Ransomware (2017)**
- **Issue:** Unpatched systems (MS17-010 vulnerability)
- **Impact:** Global, 200,000+ computers, healthcare disruption
- **Lesson:** Critical importance of patch management

---

## 16. FOUR SECURITY STRATEGIES

### 1. OBSCURITY STRATEGY

**Overview:** Relies on concealing system design, implementation, or configuration details.

**Key Features:**
- Concealment and unpredictability
- Hides architecture, processes, software versions
- Examples: Non-standard ports, hidden version numbers
- Depends on secrecy

**Advantages:**
- Additional layer of difficulty for attackers
- Protects sensitive information that doesn't need to be public

**Disadvantages:**
- **Once discovered, security fails**
- Unrealistic assumption that attackers can't obtain hidden details
- Not a substitute for real security

**Verdict:** Use as supplementary layer, never as primary defense

---

### 2. PERIMETER DEFENSE STRATEGY

**Overview:** Protects network's outer boundary to prevent unauthorized access. Like a fortress with a moat.

**Key Features:**
- **Firewalls:** Block/permit traffic based on rules
- **IDS/IPS:** Monitor for suspicious activities
- **Gateways and Proxies:** Control traffic between internal/external networks

**Advantages:**
- Easy to implement in smaller networks
- First line of defense against external threats

**Disadvantages:**
- **Insufficient against insider threats**
- **Obsolete in modern environments:** Remote work, cloud, mobile devices
- **Single point of failure:** If breached, little remaining defense

**Verdict:** Insufficient alone for modern organizations

---

### 3. DEFENSE IN DEPTH (DiD) STRATEGY

**Overview:** Layered security using multiple levels of defense. If one layer fails, others continue protecting.

**Key Features:**
- Multiple layers at different levels (network, application, host, data)
- Redundancy built-in
- Combines technical, physical, and administrative controls

**Advantages:**
- **Resilience:** Multiple layers must be bypassed
- **Comprehensive:** Protects against internal and external threats
- **Flexible:** Adapts to new threats

**Disadvantages:**
- **Complexity and cost:** Requires significant resources
- **Potential overlap:** Some redundancy may be inefficient

### Defense in Depth: 10-Layer Model

**Core:** Critical Objects
- Most valuable assets requiring protection

**IA Baseline**
- Minimum security standards for all systems

**Layer 1: IA Policies**
- Defines required actions and behaviors
- Foundation for all other layers

**Layer 2: IA Management**
- Monitors and controls policy implementation
- Oversees compliance

**Layer 3: IA Architecture (Technical Infrastructure)**
- Integrates technical and non-technical controls
- Three security levels:
  - Physical security
  - Procedural security
  - Logical security

**Layer 4: Operational Security Administration**
- User management (general and privileged)
- Separation of roles, accountability
- Detection and deterrence
- Outsourcing considerations

**Layer 5: Configuration Management**
- Documents all changes
- Identifies effects on cost/schedule
- Maintains integrity
- Communicates changes to appropriate personnel

**Layer 6: Life-Cycle Security**
- Security in each stage:
  - Initiation
  - Definition
  - Design
  - Acquisition
  - Development and Implementation
  - Operation and Maintenance
  - Destruction and Disposal

**Layer 7: Contingency Planning**
- Planning for worst-case scenarios
- Backups and power outage plans
- Emergency action/disaster recovery
- Continuity of operations (COOP)

**Layer 8: IA Education, Training, and Awareness**
- IA support services
- Awareness programs
- Curriculum development
- Certification and accreditation
- Compliance inspection
- Workshops and symposia

**Layer 9: IA Policy Compliance Oversight**
- Detects, reports, and corrects non-compliance
- Tools:
  - Intrusion detection systems
  - Vulnerability scanners
  - IP address monitoring
  - Automated auditing
  - Virus detectors
  - Periodic assessments

**Layer 10: IA Incident Response & Reporting**
- Accepts that incidents will occur
- General procedures:
  - Determine appropriate response
  - Collect and safeguard information
  - Contain the situation
  - Assemble incident management team

**Verdict:** Industry-standard approach, highly recommended

---

### 4. ZERO TRUST STRATEGY

**Overview:** Assumes **no user or device is trustworthy by default**, whether inside or outside the network. Continuous verification is required.

**Key Principles:**

1. **Never Trust, Always Verify**
   - No implicit trust based on network location
   - Every access request must be authenticated and authorized

2. **Least Privilege Access**
   - Users get minimum permissions needed
   - Just-in-time, just-enough-access (JIT/JEA)

3. **Micro-Segmentation**
   - Networks divided into small, isolated segments
   - Limits lateral movement after breach

**Advantages:**
- **Improved security:** Continuous verification reduces breach risk
- **Minimized attack surface:** Limits exploitation pathways
- **Adaptable to modern environments:** Works with cloud, remote work, BYOD

**Disadvantages:**
- **Complex implementation:** Significant changes to network architecture
- **Potential user friction:** Continuous verification may impact usability
- **Cost:** Requires investment in new technologies and training

**Verdict:** Modern approach essential for today's distributed environments

---

## 17. RECOMMENDED ELEMENTS OF NATIONAL CYBERSECURITY STRATEGY

Based on ITU, ENISA, EU, OAS, OECD, Microsoft recommendations:

**Universally Recommended (All 6 Organizations):**
1. Top-level government support
2. CSIRT/CERT teams
3. Public-private partnership/cooperation
4. International cooperation

**Widely Recommended:**
- National Cybersecurity Coordinator
- National Focal Point Organization
- Legal framework
- National cybersecurity framework
- Cybersecurity education and awareness
- Cybersecurity workforce skills training
- Technical guidelines/security baselines
- Cyber exercise and contingency plans

---

## PRACTICE QUESTIONS

### Question 1: Threat Categories
**A ransomware attack encrypts all files on a company's servers and demands payment. Which threat category does this primarily represent?**
A) Disclosure
B) Deception
C) Disruption
D) Usurpation

**Answer:** C) Disruption - Ransomware prevents legitimate access to resources (availability violation).

---

### Question 2: Security Controls
**A company requires employees to take mandatory 2-week vacations annually. What type of control is this?**
A) Technical preventive
B) Administrative detective
C) Physical deterrent
D) Administrative preventive

**Answer:** D) Administrative preventive - Though it has detective qualities (someone else may discover fraud during vacation), its primary purpose is preventive by reducing opportunity for insider threats.

---

### Question 3: Biometrics
**A biometric system has a 3% FAR and 8% FRR. To make it more user-friendly, you adjust the sensitivity. What happens?**
A) Both FAR and FRR decrease
B) FAR decreases, FRR increases
C) FAR increases, FRR decreases
D) Both FAR and FRR increase

**Answer:** C) FAR increases, FRR decreases - Making the system more user-friendly (lower FRR) means accepting more users, which increases the chance of accepting unauthorized users (higher FAR).

---

### Question 4: Authentication
**Which OTP method uses passwords in REVERSE order?**
A) Time-Synchronization (TOTP)
B) Challenge-Response
C) Hash Chain
D) All of the above

**Answer:** C) Hash Chain - h(s)=p1, h(p1)=p2... but passwords are used as: pn, pn-1, ..., p2, p1

---

### Question 5: FIDO2
**What makes FIDO2 resistant to phishing attacks?**
A) It uses very strong passwords
B) Private keys never leave the user's device
C) It requires biometric authentication
D) It sends encrypted passwords to the server

**Answer:** B) Private keys never leave the user's device - Even if a user is tricked into visiting a fake website, the private key cannot be stolen because it's stored locally.

---

### Question 6: SSO
**In an SSO system, what component is responsible for authenticating users and issuing tokens?**
A) Service Provider (SP)
B) Relying Party (RP)
C) Identity Provider (IdP)
D) Authentication Server (AS)

**Answer:** C) Identity Provider (IdP) - The IdP authenticates users and issues tokens that SPs trust.

---

### Question 7: Security Strategies
**Which security strategy is considered obsolete for modern cloud and remote work environments?**
A) Obscurity Strategy
B) Perimeter Defense Strategy
C) Defense in Depth Strategy
D) Zero Trust Strategy

**Answer:** B) Perimeter Defense Strategy - Modern environments with cloud services, remote work, and mobile devices don't have a clear "perimeter" to defend.

---

### Question 8: Defense in Depth Layers
**In the Defense in Depth 10-layer model, which layer includes incident response and reporting?**
A) Layer 7: Contingency Planning
B) Layer 9: IA Policy Compliance Oversight
C) Layer 10: IA Incident Response & Reporting
D) Layer 8: IA Education, Training, and Awareness

**Answer:** C) Layer 10: IA Incident Response & Reporting - This is the outermost layer dealing with actual security incidents.

---

### Question 9: Zero Trust
**Which principle is NOT a core component of Zero Trust?**
A) Never Trust, Always Verify
B) Least Privilege Access
C) Trust Internal Network Users
D) Micro-Segmentation

**Answer:** C) Trust Internal Network Users - Zero Trust explicitly does NOT trust anyone by default, whether internal or external.

---

### Question 10: Recent Attacks
**The Twilio and Cloudflare phishing attack (2022) succeeded despite MFA being in place. Why?**
A) MFA was not implemented correctly
B) Attackers used zero-day exploits
C) SMS and OTP-based MFA are not phishing-resistant
D) Employees disabled MFA

**Answer:** C) SMS and OTP-based MFA are not phishing-resistant - Attackers created fake login portals that captured OTP codes in real-time.

---

## KEY TAKEAWAYS

### Top Priority Topics
1. **Understand the four threat categories** and how to map real incidents to them
2. **Know the difference between logging and auditing**
3. **Understand FAR, FRR, and CER** for biometric systems
4. **Know FIDO2 architecture** (CTAP, WebAuthn, registration/authentication phases)
5. **Understand SSO flow** and the role of IdP vs SP
6. **Compare and contrast the four security strategies** (Obscurity, Perimeter, DiD, Zero Trust)
7. **Memorize the 10 layers of Defense in Depth** in order
8. **Understand recent authentication attacks** and their weaknesses

### Common Exam Traps
- Confusing FRR (Type I) with FAR (Type II)
- Thinking Perimeter Defense is sufficient for modern networks
- Assuming Obscurity Strategy provides real security
- Confusing authentication (who you are) with authorization (what you can do)
- Not understanding the trade-off between FAR and FRR
- Forgetting that administrative controls are the foundation

### Study Tips
1. Create flashcards for the 10 DiD layers
2. Practice mapping real-world incidents to threat categories
3. Draw the FIDO2 and SSO authentication flows from memory
4. Make a comparison table of the four security strategies
5. Review the recent authentication attacks and their specific weaknesses
6. Understand WHY each countermeasure works, not just WHAT it is

---

**End of Study Guide - Good Luck on Your Exam!**

*Remember to create a new chat for the remaining topics: Risk Analysis, CVSS v4.0, LLM Security, and CTF Education.*
