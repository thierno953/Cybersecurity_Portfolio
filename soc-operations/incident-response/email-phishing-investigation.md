# 1 - Email Phishing Investigation - Advanced Header & OSINT Analysis

## Executive Summary

**Threat Classification**: Phishing Scam (Advance-Fee Fraud)  
**Risk Level**: High  
**Disposition**: Malicious - Recommended Block

## Investigation Overview

As part of SOC training, I conducted a comprehensive email forensic analysis to identify phishing indicators through header analysis, authentication verification, and OSINT correlation.

### Download

- [First_Email.zip](/soc-operations/incident-response/First_Email.zip)

## Key Findings

### Critical Indicators

- **SPF Softfail** - Sender IP not authorized
- **From/Reply-To Mismatch** - Classic impersonation tactic
- **Suspicious Infrastructure** - Chinese mail server involved in spam campaigns
- **Social Engineering** - "16 million USD" advance-fee lure

## Technical Analysis

### Step 1: Received Headers Analysis

![Email Phishing](/soc-operations/incident-response/assets/01_First_Email_Analysis.png)
_7 Received headers showing email path from source to destination_

![Email Phishing](/soc-operations/incident-response/assets/02_First_Email_Analysis.png)
_Detailed header information_

![Email Phishing](/soc-operations/incident-response/assets/03_First_Email_Analysis.png)
_Complete header chain analysis_

### Step 2: Originating Server Identification

![Email Phishing](/soc-operations/incident-response/assets/04_First_Email_Analysis.png)
_Originating mail server: mail.yobow.cn from IP 183.56.179.169_

### Step 3: Authentication Results

![Email Phishing](/soc-operations/incident-response/assets/05_First_Email_Analysis.png)
_SPF softfail with no DKIM/DMARC configuration_

### Step 4: Header Inconsistencies

![Email Phishing](/soc-operations/incident-response/assets/06_First_Email_Analysis.png)
_From: p.chambers@sasktel.net_

![Email Phishing](/soc-operations/incident-response/assets/07_First_Email_Analysis.png)
_Reply-To: Gmail address - clear mismatch_

### Step 5: Email Metadata

![Email Phishing](/soc-operations/incident-response/assets/08_First_Email_Analysis.png)
_Subject: "Attention Dear Beneficiary" - social engineering trigger_

![Email Phishing](/soc-operations/incident-response/assets/09_First_Email_Analysis.png)
_Email date: Wed, 6 Dec 2023 05:00:12 -0800_

![Email Phishing](/soc-operations/incident-response/assets/10_First_Email_Analysis.png)
_Content-Type: text/html - HTML content used_

![Email Phishing](/soc-operations/incident-response/assets/11_First_Email_Analysis.png)
_Additional header information_

### Step 6: Technical Headers

![Email Phishing](/soc-operations/incident-response/assets/12_First_Email_Analysis.png)
_X-Mailer: Microsoft Outlook Express_

![Email Phishing](/soc-operations/incident-response/assets/13_First_Email_Analysis.png)
_Message-ID: 20231206125957.6414E20EB5FD@mail.yobow.cn_

![Email Phishing](/soc-operations/incident-response/assets/14_First_Email_Analysis.png)
_Return-Path: p.chambers@sasktel.net_

![Email Phishing](/soc-operations/incident-response/assets/15_First_Email_Analysis.png)
_Recipient information_

### Step 7: Email Body Analysis

![Email Phishing](/soc-operations/incident-response/assets/16_First_Email_Analysis.png)
_Advance-fee fraud offering 16 million USD with contact details_

## OSINT Investigation

### Step 8: Domain Investigation - mail.yobow.cn

![Email Phishing](/soc-operations/incident-response/assets/17_First_Email_Analysis.png)
_DomainTools investigation interface_

![Email Phishing](/soc-operations/incident-response/assets/18_First_Email_Analysis.png)
_Domain created 2014-07-18 in Beijing, China_

![Email Phishing](/soc-operations/incident-response/assets/19_First_Email_Analysis.png)
_Complete domain registration details_

### Step 9: Legitimate Domain Verification - sasktel.net

![Email Phishing](/soc-operations/incident-response/assets/20_First_Email_Analysis.png)
_Legitimate Canadian ISP domain information_

![Email Phishing](/soc-operations/incident-response/assets/21_First_Email_Analysis.png)
_Clean reputation on VirusTotal_

![Email Phishing](/soc-operations/incident-response/assets/22_First_Email_Analysis.png)
_Confirmation as legitimate ISP_

### Step 10: IP Reputation Check

![Email Phishing](/soc-operations/incident-response/assets/23_First_Email_Analysis.png)
_IP 183.56.179.169 with multiple spam reports_

### Step 11: Authentication Deep Dive

![Email Phishing](/soc-operations/incident-response/assets/24_First_Email_Analysis.png)
_Detailed SPF softfail analysis_

![Email Phishing](/soc-operations/incident-response/assets/25_First_Email_Analysis.png)
_No DKIM configuration found_

![Email Phishing](/soc-operations/incident-response/assets/26_First_Email_Analysis.png)
_No DMARC configuration found_

![Email Phishing](/soc-operations/incident-response/assets/27_First_Email_Analysis.png)
_Complete authentication results summary_

## IOC Extraction

### Step 12: Key Indicators Extraction

![Email Phishing](/soc-operations/incident-response/assets/28_First_Email_Analysis.png)
_SPF: softfail - IP not authorized_

![Email Phishing](/soc-operations/incident-response/assets/29_First_Email_Analysis.png)
_Sender IP: 183.56.179.169_

![Email Phishing](/soc-operations/incident-response/assets/30_First_Email_Analysis.png)
_DKIM/DMARC: None configured_

![Email Phishing](/soc-operations/incident-response/assets/31_First_Email_Analysis.png)
_Closest mail server: mail.yobow.cn_

![Email Phishing](/soc-operations/incident-response/assets/32_First_Email_Analysis.png)
_Email date confirmation_

![Email Phishing](/soc-operations/incident-response/assets/33_First_Email_Analysis.png)
_Sender domain creation date: 2000-04-05_

![Email Phishing](/soc-operations/incident-response/assets/34_First_Email_Analysis.png)
_Reply-To: agentcynthiajamescontact01@gmail.com_

![Email Phishing](/soc-operations/incident-response/assets/35_First_Email_Analysis.png)
_Subject: Attention Dear Beneficiary_

![Email Phishing](/soc-operations/incident-response/assets/36_First_Email_Analysis.png)
_Return-Path: p.chambers@sasktel.net_

![Email Phishing](/soc-operations/incident-response/assets/37_First_Email_Analysis.png)
_Content-Type: text/html_

![Email Phishing](/soc-operations/incident-response/assets/38_First_Email_Analysis.png)
_Message-ID confirmation_

![Email Phishing](/soc-operations/incident-response/assets/39_First_Email_Analysis.png)
_Fraudulent contact emails_

![Email Phishing](/soc-operations/incident-response/assets/40_First_Email_Analysis.png)
_Root domain creation and location_

![Email Phishing](/soc-operations/incident-response/assets/41_First_Email_Analysis.png)
_Spam reports on AbuseIPDB_

## Mitigation Recommendations

### Immediate Actions

1. **Block IP** 183.56.179.169 at network perimeter
2. **Quarantine** similar messages with "Beneficiary" subject lines
3. **Alert** on SPF softfail + From/Reply-To mismatches

### Long-term Controls

1. **Enforce DMARC** policy for organizational domains
2. **User Awareness** training on advance-fee fraud
3. **SIEM Rules** for authentication failure correlation

## IOC (Indicators of Compromise)

### Domains

- `mail.yobow.cn` - C2 Infrastructure
- `sasktel.net` - Spoofed Legitimate Domain

### Email Addresses

- `agentcynthiajamescontact01@gmail.com` - Attacker Contact
- `dr.philipmaxwell303@gmail.com` - Attacker Contact

### IP Addresses

- `183.56.179.169` - Originating Malicious IP

## Conclusion

This investigation demonstrates a **sophisticated phishing operation** using legitimate infrastructure spoofing combined with psychological manipulation. The absence of DKIM/DMARC allowed successful delivery despite SPF softfail.

**Confidence Level**: High - Definite phishing attempt  
**Impact**: Financial fraud risk through advance-fee scam

---

_All forensic evidence preserved and documented for potential incident response procedures._

---

---

# 2 - Advanced Phishing Investigation - Credential Harvesting Campaign

## Executive Summary

**Threat Classification**: Credential Harvesting Phishing  
**Risk Level**: Critical  
**Disposition**: Malicious - Multi-vector Attack

## Campaign Overview

Sophisticated phishing campaign using Microsoft infrastructure spoofing combined with base64-encoded HTML impersonating PDF attachments for credential theft.

### Download

- [Second_Email.zip](/soc-operations/incident-response/Second_Email.zip)

## Key Findings

### Critical Indicators

- **Legitimate Infrastructure Abuse** - Microsoft Office 365 infrastructure exploited
- **File Extension Spoofing** - HTML masquerading as PDF attachment
- **Multi-layer Obfuscation** - Base64 encoding + fake file extensions
- **Credential Harvesting** - Google Apps Script phishing page

## Technical Analysis

### Step 1: Infrastructure Analysis

![Advanced Phishing](/soc-operations/incident-response/assets/01_Second_Email_Analysis.png)

_Email routing through Microsoft Office 365 infrastructure_

![Advanced Phishing](/soc-operations/incident-response/assets/02_Second_Email_Analysis.png)
_Complete header chain showing Microsoft mail servers_

![Advanced Phishing](/soc-operations/incident-response/assets/03_Second_Email_Analysis.png)
_Message-ID confirming Office 365 origination_

### Step 2: Sender Identification

![Advanced Phishing](/soc-operations/incident-response/assets/04_Second_Email_Analysis.png)
_Sender IP identification through authentication headers_

![Advanced Phishing](/soc-operations/incident-response/assets/05_Second_Email_Analysis.png)
_Sender IP: 40.107.215.98 (Microsoft infrastructure)_

### Step 3: Email Metadata Analysis

![Advanced Phishing](/soc-operations/incident-response/assets/06_Second_Email_Analysis.png)
_Email timestamp and recipient information_

![Advanced Phishing](/soc-operations/incident-response/assets/07_Second_Email_Analysis.png)
_From: noreply@Quick Response vs Actual: comunidadeduar.com.ar_

![Advanced Phishing](/soc-operations/incident-response/assets/08_Second_Email_Analysis.png)
_Subject: "We locked your account for security reason"_

### Step 4: User Agent Forensics

![Advanced Phishing](/soc-operations/incident-response/assets/09_Second_Email_Analysis.png)
_X-Mailer showing webmail user agent_

![Advanced Phishing](/soc-operations/incident-response/assets/10_Second_Email_Analysis.png)
_Chrome on macOS - attacker system fingerprint_

### Step 5: Content Structure

![Advanced Phishing](/soc-operations/incident-response/assets/11_Second_Email_Analysis.png)
_Content-Type: multipart/mixed with boundaries_

![Advanced Phishing](/soc-operations/incident-response/assets/12_Second_Email_Analysis.png)
_Return-Path for non-delivery notifications_

### Step 6: URL Analysis

![Advanced Phishing](/soc-operations/incident-response/assets/13_Second_Email_Analysis.png)
_Mixed legitimate (Facebook) and suspicious URLs_

![Advanced Phishing](/soc-operations/incident-response/assets/14_Second_Email_Analysis.png)
_script.google.com/exec/ - Google Apps Script abuse_

### Step 7: Attachment Analysis

![Advanced Phishing](/soc-operations/incident-response/assets/15_Second_Email_Analysis.png)
_Base64-encoded content disguised as PDF_

![Advanced Phishing](/soc-operations/incident-response/assets/16_Second_Email_Analysis.png)
_Content-Disposition: attachment; filename="Document.pdf"_

### Step 8: Base64 Decoding

![Advanced Phishing](/soc-operations/incident-response/assets/17_Second_Email_Analysis.png)
_CyberChef base64 decoding process_

![Advanced Phishing](/soc-operations/incident-response/assets/18_Second_Email_Analysis.png)
_Revealed HTML content, not PDF_

### Step 9: File Type Verification

![Advanced Phishing](/soc-operations/incident-response/assets/19_Second_Email_Analysis.png)
_Linux file command confirms HTML content_

![Advanced Phishing](/soc-operations/incident-response/assets/20_Second_Email_Analysis.png)
_Decoded HTML phishing page content_

![Advanced Phishing](/soc-operations/incident-response/assets/21_Second_Email_Analysis.png)
_Clear evidence of file extension spoofing_

### Step 10: Authentication Analysis

![Advanced Phishing](/soc-operations/incident-response/assets/22_Second_Email_Analysis.png)
_SPF: pass | DKIM: none | DMARC: bestguesspass_

### Step 11: Domain OSINT

![Advanced Phishing](/soc-operations/incident-response/assets/23_Second_Email_Analysis.png)
_comunidadeduar.com.ar - Created 2013-07-10, Argentina_

![Advanced Phishing](/soc-operations/incident-response/assets/24_Second_Email_Analysis.png)
_VirusTotal phishing associations_

![Advanced Phishing](/soc-operations/incident-response/assets/25_Second_Email_Analysis.png)
_Multiple security vendor flags_

### Step 12: URL Threat Analysis

![Advanced Phishing](/soc-operations/incident-response/assets/26_Second_Email_Analysis.png)
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
