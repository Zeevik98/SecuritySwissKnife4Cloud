##Overview
This repository contains AWS security automation tools for incident response, forensics investigation, and security controls implementation.

##Structure
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
 
##What do we have here?
Bedrock4Cyber
*AI-powered security analysis and response
*Integration guides and prerequisites
*Step-by-step implementation instructions

#Incident Response
Forensics & Investigation
*EC2/ECS forensics preparation guides
*Investigation Lambda functions
*Infrastructure as Code preparation files

#Lambda Functions
*Containment functions for multiple AWS services
*Cross-account implementation support
*Automated response capabilities

#Security Controls
*Mapped to common compliance frameworks
*Cost estimations
*Quick deployment templates
*Infrastructure as Code files

##What we will need:
*AWS Account
*Required IAM permissions
*Python 3.9+
*AWS CLI
*Terraform/CloudFormation for IAC deployment

Documentation
Detailed documentation for each component can be found in their respective directories.
Security Note
Please review all code and configurations before deployment in your environment.

License
This project is licensed under the GPL-3.0 License - see the LICENSE file for details.
