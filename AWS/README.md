# Security Swiss Knife 4 Cloud

## Overview
This repository contains AWS security automation tools for incident response, forensics investigation, and security controls implementation.

## WHAT DO WE HAVE HERE?
**BEDROCK4CYBER:**\
-AI-powered security analysis and response\
-Integration guides and prerequisites\
-Step-by-step implementation instructions

 **Security Scanner**:\
-Basic Security Analysis: Security headers inspection, SSL/TLS configuration checks, and certificate validation.\
-Active Testing: SQL injection attempts, Cross-Site Scripting (XSS) detection, and directory traversal testing.\
-Input Validation: Tests for proper validation of email, phone numbers, and date formats in application inputs.\
-Results Management: Automated scanning results saved to S3 in JSON format for further analysis and integration.


**Forensics & Investigation:**\
-EC2/ECS forensics preparation guides\
-Investigation Lambda functions\
-Infrastructure as Code preparation files

**Lambda Functions:**\
-Containment functions for multiple AWS services\
-Cross-account implementation support\
-Automated response capabilities


## Directory Structure
```text
AWS/
├── Bedrock4Cyber/
│   ├── Prerequisites/
│   └── Step By Step guide/
└── Incident-Response/
    ├── Forensics gathering & Investigation/
    │   ├── EC2 forensics prep(Linux)
    │   ├── EC2_Investigation_Lambda
    │   ├── ECS forensics prep(Linux)
    │   ├── ECS_Investigation_Lambda
    │   └── IAC PREP FILE
    ├── Lambda-Functions/
    │   ├── EC2Containment_Lambda
    │   ├── ECS_Containment_Lambda
    │   ├── EKS_Containment_Lambda
    │   ├── IAM_CONTAINMENT_Lambda
    │   ├── RDS_Containment_Lambda
    │   └── S3_Containment_Lambda
    ├── Controls covered map
    ├── Cost estimation
    ├── Quick and Easy controls IAC files
    └── Quick and Easy controls templates
