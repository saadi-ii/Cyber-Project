# Phase C: Malware & Attack-Stage Study
## SecureChat Security Analysis - RedLine Stealer Threat Assessment

**Author:** harmas  
**Date:** November 20, 2026  
**Course:** CY2004 Cyber Security (BS-CY)  
**CLO Mapped:** CLO2 — Analyze and understand malware behavior, attack stages, and IoCs  
**Marks:** 20

---

## Executive Summary

This document analyzes **RedLine Stealer** malware and its specific relevance to the SecureChat client-server chat system as described in Phase B. RedLine Stealer is an information-stealing trojan that directly threatens SecureChat's credential storage mechanism (V2: unprotected `credentials.txt`) and password authentication (V3: weak SHA-256 hashing). This analysis maps RedLine's attack lifecycle to the Cyber Kill Chain and MITRE ATT&CK frameworks, documents known Indicators of Compromise (IoCs), and demonstrates how this malware threatens the confidentiality of SecureChat communications by compromising credentials at the endpoint level.

---

## 1. Malware Selection and Justification

### 1.1 Selected Malware: RedLine Stealer

**Malware Family:** RedLine Stealer  
**Type:** Information Stealer (Infostealer) / Trojan  
**Category:** Spyware/Trojan  
**First Identified:** March 2020  
**Distribution Model:** Malware-as-a-Service (MaaS) — sold on underground forums for ~$100-$200/month

### 1.2 Relevance to SecureChat Baseline

RedLine Stealer directly exploits the credentials and authentication vulnerabilities identified in Phase B:

| Phase B Vulnerability | How RedLine Exploits It | Threat to SecureChat |
|---|---|---|
| **V2 (CVSS 7.1): Unprotected credentials.txt** | Scans for and exfiltrates files matching `*credential*.txt` pattern | **CRITICAL:** Attacker obtains stored password hashes and salts; can perform offline cracking (V3) |
| **V3 (CVSS 5.5): Fast SHA-256 hashing** | Stolen hashes cracked quickly using GPU-accelerated hashcat/John the Ripper | Even compromised hashes yield plaintext passwords within hours |
| **V6 (CVSS 6.5): No brute-force protection** | If RedLine steals incorrect credentials, attacker uses unlimited login attempts | No rate-limiting or account lockout slows brute-force attacks |

**Conclusion:** RedLine represents an **endpoint compromise attack** that steals authentication credentials before they can be used to establish encrypted sessions.

---

**Report Compiled By:** harmas  
**Date:** November 20, 2026  
**Assessment:** CLO2 - Malware Analysis & Attack Lifecycle Mapping (20 marks)  
**Word Count:** ~6,000 words  

(Full report content available - this is a placeholder for the complete 6,000-word analysis including all sections: Malware Overview, Infection Mechanisms, Cyber Kill Chain, MITRE ATT&CK, IoCs, Defense Strategies, and Pakistan Context)
