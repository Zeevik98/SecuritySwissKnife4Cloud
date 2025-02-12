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
                "ec2:CreateVpc",
                "ec2:CreateSubnet",
                "ec2:CreateRouteTable",
                "ec2:CreateSecurityGroup",
                "ec2:AttachInternetGateway",
                "ec2:CreateInternetGateway",
                "ec2:AssociateRouteTable",
                "ec2:ModifyVpcAttribute",
                "iam:ListInstanceProfiles",
                "iam:RemoveRoleFromInstanceProfile",
                "iam:ListInstanceProfilesForRole",
                "ec2:DisassociateIamInstanceProfile",
                "wafv2:UpdateIPSet",
                "kms:Encrypt",
                "sns:Publish"
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


