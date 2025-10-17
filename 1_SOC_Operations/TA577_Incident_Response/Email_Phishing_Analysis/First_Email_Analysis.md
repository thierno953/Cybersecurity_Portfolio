# Email Phishing Investigation - Advanced Header & OSINT Analysis

## Executive Summary

**Threat Classification**: Phishing Scam (Advance-Fee Fraud)  
**Risk Level**: High  
**Disposition**: Malicious - Recommended Block

## Investigation Overview

As part of SOC training, I conducted a comprehensive email forensic analysis to identify phishing indicators through header analysis, authentication verification, and OSINT correlation.

### Download

- [First_Email.zip](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/First_Email.zip)

## Key Findings

### Critical Indicators

- **SPF Softfail** - Sender IP not authorized
- **From/Reply-To Mismatch** - Classic impersonation tactic
- **Suspicious Infrastructure** - Chinese mail server involved in spam campaigns
- **Social Engineering** - "16 million USD" advance-fee lure

## Technical Analysis

### Step 1: Received Headers Analysis

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/01_First_Email_Analysis.png)
_7 Received headers showing email path from source to destination_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/02_First_Email_Analysis.png)
_Detailed header information_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/03_First_Email_Analysis.png)
_Complete header chain analysis_

### Step 2: Originating Server Identification

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/04_First_Email_Analysis.png)
_Originating mail server: mail.yobow.cn from IP 183.56.179.169_

### Step 3: Authentication Results

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/05_First_Email_Analysis.png)
_SPF softfail with no DKIM/DMARC configuration_

### Step 4: Header Inconsistencies

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/06_First_Email_Analysis.png)
_From: p.chambers@sasktel.net_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/07_First_Email_Analysis.png)
_Reply-To: Gmail address - clear mismatch_

### Step 5: Email Metadata

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/08_First_Email_Analysis.png)
_Subject: "Attention Dear Beneficiary" - social engineering trigger_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/09_First_Email_Analysis.png)
_Email date: Wed, 6 Dec 2023 05:00:12 -0800_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/10_First_Email_Analysis.png)
_Content-Type: text/html - HTML content used_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/11_First_Email_Analysis.png)
_Additional header information_

### Step 6: Technical Headers

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/12_First_Email_Analysis.png)
_X-Mailer: Microsoft Outlook Express_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/13_First_Email_Analysis.png)
_Message-ID: 20231206125957.6414E20EB5FD@mail.yobow.cn_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/14_First_Email_Analysis.png)
_Return-Path: p.chambers@sasktel.net_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/15_First_Email_Analysis.png)
_Recipient information_

### Step 7: Email Body Analysis

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/16_First_Email_Analysis.png)
_Advance-fee fraud offering 16 million USD with contact details_

## OSINT Investigation

### Step 8: Domain Investigation - mail.yobow.cn

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/17_First_Email_Analysis.png)
_DomainTools investigation interface_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/18_First_Email_Analysis.png)
_Domain created 2014-07-18 in Beijing, China_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/19_First_Email_Analysis.png)
_Complete domain registration details_

### Step 9: Legitimate Domain Verification - sasktel.net

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/20_First_Email_Analysis.png)
_Legitimate Canadian ISP domain information_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/21_First_Email_Analysis.png)
_Clean reputation on VirusTotal_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/22_First_Email_Analysis.png)
_Confirmation as legitimate ISP_

### Step 10: IP Reputation Check

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/23_First_Email_Analysis.png)
_IP 183.56.179.169 with multiple spam reports_

### Step 11: Authentication Deep Dive

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/24_First_Email_Analysis.png)
_Detailed SPF softfail analysis_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/25_First_Email_Analysis.png)
_No DKIM configuration found_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/26_First_Email_Analysis.png)
_No DMARC configuration found_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/27_First_Email_Analysis.png)
_Complete authentication results summary_

## IOC Extraction

### Step 12: Key Indicators Extraction

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/28_First_Email_Analysis.png)
_SPF: softfail - IP not authorized_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/29_First_Email_Analysis.png)
_Sender IP: 183.56.179.169_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/30_First_Email_Analysis.png)
_DKIM/DMARC: None configured_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/31_First_Email_Analysis.png)
_Closest mail server: mail.yobow.cn_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/32_First_Email_Analysis.png)
_Email date confirmation_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/33_First_Email_Analysis.png)
_Sender domain creation date: 2000-04-05_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/34_First_Email_Analysis.png)
_Reply-To: agentcynthiajamescontact01@gmail.com_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/35_First_Email_Analysis.png)
_Subject: Attention Dear Beneficiary_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/36_First_Email_Analysis.png)
_Return-Path: p.chambers@sasktel.net_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/37_First_Email_Analysis.png)
_Content-Type: text/html_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/38_First_Email_Analysis.png)
_Message-ID confirmation_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/39_First_Email_Analysis.png)
_Fraudulent contact emails_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/40_First_Email_Analysis.png)
_Root domain creation and location_

![Email Phishing](/1_SOC_Operations/TA577_Incident_Response/Email_Phishing_Analysis/assets/41_First_Email_Analysis.png)
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
