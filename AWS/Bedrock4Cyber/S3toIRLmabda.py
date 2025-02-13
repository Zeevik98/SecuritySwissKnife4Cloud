#environment variable needed:FORENSICS_BUCKET: 
#Dont forget to gave the lambda excution role and the in the foransics bucket policy to modify the permissions for this actions.

import json
import boto3
import os
from botocore.exceptions import ClientError

def get_bedrock_client():
    return boto3.client('bedrock-runtime')

def get_s3_client():
    return boto3.client('s3')

def read_json_from_s3(bucket_name, file_key):
    s3_client = get_s3_client()
    try:
        response = s3_client.get_file(Bucket=bucket_name, Key=file_key)
        json_content = json.loads(response['Body'].read().decode('utf-8'))
        return json_content
    except ClientError as e:
        print(f"Error reading from S3: {e}")
        raise

def analyze_with_bedrock(findings):
    bedrock_client = get_bedrock_client()
    
    prompt = f"""Please provide an in-depth security analysis of the following IR findings:
    - Identify critical security issues
    - Suggest immediate remediation steps
    - Provide long-term recommendations
    - Highlight potential indicators of compromise
    
    Findings: {json.dumps(findings, indent=2)}
    """
    
    try:
        response = bedrock_client.invoke_model(
            modelId='anthropic.claude-v2',
            body=json.dumps({
                "prompt": prompt,
                "max_tokens": 4096,
                "temperature": 0.7
            })
        )
        
        response_body = json.loads(response['body'].read())
        return response_body['completion']
        
    except ClientError as e:
        print(f"Error calling Bedrock: {e}")
        raise

def lambda_handler(event, context):
    # Get bucket name from environment variable
    bucket_name = os.environ['FORENSICS_BUCKET']
    
    # Get the file key from the event
    file_key = event['Records'][0]['s3']['object']['key']
    
    try:
        # Read findings from S3
        findings = read_json_from_s3(bucket_name, file_key)
        
        # Analyze with Bedrock
        analysis = analyze_with_bedrock(findings)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'analysis': analysis,
                'source_file': file_key
            })
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }
