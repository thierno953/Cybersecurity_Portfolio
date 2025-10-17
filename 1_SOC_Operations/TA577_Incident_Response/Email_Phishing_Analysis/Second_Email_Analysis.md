# Advanced Phishing Investigation - Credential Harvesting Campaign

## Executive Summary

**Threat Classification**: Credential Harvesting Phishing  
**Risk Level**: Critical  
**Disposition**: Malicious - Multi-vector Attack

## Campaign Overview

Sophisticated phishing campaign using Microsoft infrastructure spoofing combined with base64-encoded HTML impersonating PDF attachments for credential theft.

### Download

- [Second_Email.zip](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/Second_Email.zip)

## Key Findings

### Critical Indicators

- **Legitimate Infrastructure Abuse** - Microsoft Office 365 infrastructure exploited
- **File Extension Spoofing** - HTML masquerading as PDF attachment
- **Multi-layer Obfuscation** - Base64 encoding + fake file extensions
- **Credential Harvesting** - Google Apps Script phishing page

## Technical Analysis

### Step 1: Infrastructure Analysis

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/01_Second_Email_Analysis.png)

_Email routing through Microsoft Office 365 infrastructure_

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/02_Second_Email_Analysis.png)
_Complete header chain showing Microsoft mail servers_

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/03_Second_Email_Analysis.png)
_Message-ID confirming Office 365 origination_

### Step 2: Sender Identification

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/04_Second_Email_Analysis.png)
_Sender IP identification through authentication headers_

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/05_Second_Email_Analysis.png)
_Sender IP: 40.107.215.98 (Microsoft infrastructure)_

### Step 3: Email Metadata Analysis

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/06_Second_Email_Analysis.png)
_Email timestamp and recipient information_

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/07_Second_Email_Analysis.png)
_From: noreply@Quick Response vs Actual: comunidadeduar.com.ar_

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/08_Second_Email_Analysis.png)
_Subject: "We locked your account for security reason"_

### Step 4: User Agent Forensics

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/09_Second_Email_Analysis.png)
_X-Mailer showing webmail user agent_

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/10_Second_Email_Analysis.png)
_Chrome on macOS - attacker system fingerprint_

### Step 5: Content Structure

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/11_Second_Email_Analysis.png)
_Content-Type: multipart/mixed with boundaries_

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/12_Second_Email_Analysis.png)
_Return-Path for non-delivery notifications_

### Step 6: URL Analysis

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/13_Second_Email_Analysis.png)
_Mixed legitimate (Facebook) and suspicious URLs_

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/14_Second_Email_Analysis.png)
_script.google.com/exec/ - Google Apps Script abuse_

### Step 7: Attachment Analysis

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/15_Second_Email_Analysis.png)
_Base64-encoded content disguised as PDF_

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/16_Second_Email_Analysis.png)
_Content-Disposition: attachment; filename="Document.pdf"_

### Step 8: Base64 Decoding

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/17_Second_Email_Analysis.png)
_CyberChef base64 decoding process_

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/18_Second_Email_Analysis.png)
_Revealed HTML content, not PDF_

### Step 9: File Type Verification

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/19_Second_Email_Analysis.png)
_Linux file command confirms HTML content_

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/20_Second_Email_Analysis.png)
_Decoded HTML phishing page content_

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/21_Second_Email_Analysis.png)
_Clear evidence of file extension spoofing_

### Step 10: Authentication Analysis

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/22_Second_Email_Analysis.png)
_SPF: pass | DKIM: none | DMARC: bestguesspass_

### Step 11: Domain OSINT

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/23_Second_Email_Analysis.png)
_comunidadeduar.com.ar - Created 2013-07-10, Argentina_

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/24_Second_Email_Analysis.png)
_VirusTotal phishing associations_

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/25_Second_Email_Analysis.png)
_Multiple security vendor flags_

### Step 12: URL Threat Analysis

![Advanced Phishing](/1_SOC_Operations/TA577_Incident_Response//Email_Phishing_Analysis/assets/26_Second_Email_Analysis.png)
_script.google.com/exec/ - Known phishing technique_

## Attack Chain Reconstruction

### Tactics, Techniques & Procedures (TTPs)

1. **Initial Access**: Email with social engineering
2. **Defense Evasion**: Base64 encoding + file spoofing
3. **Execution**: HTML content execution
4. **Collection**: Credential harvesting via fake login

### Social Engineering Elements

- **Urgency**: Account lock notification
- **Authority**: Quick Response brand impersonation
- **Fear**: Security compromise implication

## IOC (Indicators of Compromise)

### Domains

- `comunidadeduar.com.ar` - Attacker Controlled
- `script.google.com` - Phishing Delivery

### IP Addresses

- `40.107.215.98` - Microsoft Infrastructure (Legitimate)

### File Hashes

- Base64-encoded HTML attachment SHA256: [Hash would go here](https://www.freecodecamp.org/news/what-is-base64-encoding/)

### URLs

- CyberChef Github: [https://github.com/gchq/CyberChef](https://github.com/gchq/CyberChef)
- CyberChef Recipes: [https://github.com/mattnotmax/cyberchef-recipes](https://github.com/mattnotmax/cyberchef-recipes)

## Mitigation Recommendations

### Immediate Actions

1. **Block Domain** comunidadeduar.com.ar
2. **Quarantine** emails with "account locked" subjects
3. **Alert** on base64-encoded HTML attachments

### Technical Controls

1. **Attachment Sandboxing** for all email attachments
2. **URL Filtering** for Google Apps Script domains
3. **File Type Verification** beyond extensions

### User Awareness

1. **Training** on file extension spoofing
2. **Reporting** procedures for suspicious emails
3. **Verification** steps for account lock messages 

## Conclusion

This investigation uncovered a **sophisticated multi-layer phishing attack** abusing legitimate Microsoft infrastructure while employing advanced obfuscation techniques. The combination of social engineering, file spoofing, and trusted domain abuse demonstrates an evolved threat actor.

**Confidence Level**: High - Definite credential harvesting attempt  
**Impact**: Account compromise and credential theft risk

---

_This case highlights the importance of technical controls beyond basic email authentication and user education on advanced phishing tactics._
