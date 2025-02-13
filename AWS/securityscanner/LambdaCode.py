import json
import requests
import ssl
import socket
from datetime import datetime
import boto3
import urllib3
from urllib.parse import urljoin, parse_qs
import re

def perform_active_scan(url):
    """Performs active security testing"""
    vulnerabilities = []
    
    # SQL Injection Test
    test_payloads = ["'", "1' OR '1'='1", "1; DROP TABLE users"]
    for payload in test_payloads:
        try:
            response = requests.get(f"{url}?id={payload}", timeout=10)
            if any(error in response.text.lower() for error in ['sql', 'mysql', 'postgres', 'error']):
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'payload': payload,
                    'severity': 'High'
                })
        except:
            continue

    # XSS Test
    xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    for payload in xss_payloads:
        try:
            response = requests.get(f"{url}?q={payload}", timeout=10)
            if payload in response.text:
                vulnerabilities.append({
                    'type': 'XSS',
                    'payload': payload,
                    'severity': 'High'
                })
        except:
            continue

    # Directory Traversal Test
    traversal_paths = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"]
    for path in traversal_paths:
        try:
            response = requests.get(urljoin(url, path), timeout=10)
            if any(sign in response.text for sign in ['root:', '[extension]']):
                vulnerabilities.append({
                    'type': 'Directory Traversal',
                    'payload': path,
                    'severity': 'High'
                })
        except:
            continue

    return vulnerabilities

def check_input_validation(url):
    """Tests input validation"""
    validation_issues = []
    
    test_cases = [
        {'param': 'email', 'value': 'notanemail', 'check': 'Email Validation'},
        {'param': 'phone', 'value': 'abc123', 'check': 'Phone Validation'},
        {'param': 'date', 'value': 'invalid-date', 'check': 'Date Validation'}
    ]

    for test in test_cases:
        try:
            response = requests.get(f"{url}?{test['param']}={test['value']}", timeout=10)
            if response.status_code == 200:
                validation_issues.append({
                    'type': f'Weak {test["check"]}',
                    'parameter': test['param'],
                    'severity': 'Medium'
                })
        except:
            continue

    return validation_issues

def detailed_ssl_analysis(hostname):
    """Performs detailed SSL/TLS analysis"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                return {
                    'protocol_version': ssock.version(),
                    'cipher_suite': cipher[0],
                    'cert_expiry': cert['notAfter'],
                    'cert_issuer': cert['issuer'],
                    'supports_perfect_forward_secrecy': 'ECDHE' in cipher[0] or 'DHE' in cipher[0]
                }
    except Exception as e:
        return {'error': str(e)}

def scan_endpoint(url):
    """Enhanced security scan of an endpoint"""
    try:
        results = {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'basic_security': {},
            'active_tests': {},
            'input_validation': {},
            'ssl_analysis': {}
        }
        
        # Basic Security Headers
        response = requests.get(url, timeout=30)
        headers = response.headers
        results['basic_security'] = {
            'headers': {
                'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing')
            },
            'status_code': response.status_code
        }
        
        # Active Vulnerability Testing
        results['active_tests'] = perform_active_scan(url)
        
        # Input Validation Testing
        results['input_validation'] = check_input_validation(url)
        
        # Detailed SSL/TLS Analysis
        hostname = urllib3.util.url.parse_url(url).host
        results['ssl_analysis'] = detailed_ssl_analysis(hostname)
        
        return results
        
    except Exception as e:
        return {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'error': str(e)
        }

def save_results(results, bucket, key):
    """Saves scan results to S3"""
    s3 = boto3.client('s3')
    json_results = json.dumps(results, indent=2)
    
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json_results,
        ContentType='application/json'
    )
    
    return f"s3://{bucket}/{key}"

def lambda_handler(event, context):
    endpoints = event['endpoints']
    s3_bucket = event['s3_bucket']
    
    results = {
        'scan_time': datetime.now().isoformat(),
        'scans': {}
    }
    
    for endpoint in endpoints:
        results['scans'][endpoint] = scan_endpoint(endpoint)
    
    file_key = f"scans/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    s3_path = save_results(results, s3_bucket, file_key)
    
    return {
        'statusCode': 200,
        'body': {
            'message': 'Enhanced scan completed',
            'results_location': s3_path,
            'summary': {
                'endpoints_scanned': len(endpoints),
                'scan_time': results['scan_time']
            }
        }
    }
