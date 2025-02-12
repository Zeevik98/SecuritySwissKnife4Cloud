Name: IR-Containment-Lambda

Description:
Automated incident response lambda that isolates potentially compromised EC2 instances, creates forensic snapshots, blocks malicious IPs at WAF/VPC level, and coordinates with investigation lambda.

Execution Role Name: Custome, need to have the following permissions:
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateSnapshot",
                "ec2:CreateImage",
                "ec2:ModifyInstanceAttribute",
                "ec2:StopInstances",
                "ec2:CreateTags",
                "ec2:DescribeInstances",
                "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:ModifySecurityGroupRules",
                "wafv2:UpdateIPSet",
                "wafv2:GetIPSet",
                "kms:Encrypt",
                "kms:Decrypt",
                "lambda:InvokeFunction",
                "sns:Publish",
                "iam:ListRoles",
                "iam:ListInstanceProfiles",
                "cloudtrail:LookupEvents",
                "cloudwatch:PutMetricData"
            ],
            "Resource": "*"
        }
    ]
}


Other policy updates needed:
1.WAF IP set policy to allow updates(If not relvant for you org than comment it out)
2.KMS policy to allow encryption\decryption actions(HAve to have according to best practice)
3.CloudWatch policy for metrics and logs(Or any other alternative solution used in your organisation)

Variable list:
ENVIRONMENT_VARIABLES = {
    'INVESTIGATION_LAMBDA_ARN': 'arn:aws:lambda:region:account:function:investigation-lambda',
    'SECURITY_TEAM_SNS_TOPIC': 'arn:aws:sns:region:account:security-notifications',
    'WAF_IPSET_ID': 'ipset-id',
    'WAF_IPSET_NAME': 'blocked-ips',
    'KMS_KEY_ID': 'key-id',
    'FORENSICS_BUCKET': 'forensics-bucket-name'
}


