#!/usr/bin/env python3
"""
Setup CloudFront distribution with S3 Origin Access Control (OAC)
for secure access to dashboard assets
"""

import boto3
import json
import time
from datetime import datetime

def setup_cloudfront_s3():
    """Setup CloudFront distribution with OAC for S3 bucket access"""
    
    # Initialize AWS clients
    s3 = boto3.client('s3')
    cloudfront = boto3.client('cloudfront')
    
    bucket_name = 'honeypot-dashboard-assets-962265335633'
    
    print("🚀 Setting up CloudFront distribution with S3 OAC...")
    
    try:
        # Step 1: Create Origin Access Control (OAC)
        print("📝 Creating Origin Access Control...")
        
        oac_config = {
            'Name': 'honeypot-dashboard-oac',
            'Description': 'OAC for honeypot dashboard assets',
            'OriginAccessControlConfig': {
                'Name': 'honeypot-dashboard-oac',
                'Description': 'Origin Access Control for honeypot dashboard S3 bucket',
                'SigningProtocol': 'sigv4',
                'SigningBehavior': 'always',
                'OriginAccessControlOriginType': 's3'
            }
        }
        
        try:
            oac_response = cloudfront.create_origin_access_control(
                OriginAccessControlConfig=oac_config['OriginAccessControlConfig']
            )
            oac_id = oac_response['OriginAccessControl']['Id']
            print(f"✅ Created OAC with ID: {oac_id}")
        except cloudfront.exceptions.OriginAccessControlAlreadyExists:
            # List existing OACs to find ours
            oacs = cloudfront.list_origin_access_controls()
            for oac in oacs['OriginAccessControlList']['Items']:
                if oac['Name'] == 'honeypot-dashboard-oac':
                    oac_id = oac['Id']
                    print(f"✅ Using existing OAC with ID: {oac_id}")
                    break
        
        # Step 2: Create CloudFront distribution
        print("☁️ Creating CloudFront distribution...")
        
        distribution_config = {
            'CallerReference': f'honeypot-dashboard-{int(time.time())}',
            'Comment': 'CloudFront distribution for honeypot dashboard assets',
            'DefaultRootObject': 'architecture-diagram.png',
            'Origins': {
                'Quantity': 1,
                'Items': [
                    {
                        'Id': f'{bucket_name}-origin',
                        'DomainName': f'{bucket_name}.s3.amazonaws.com',
                        'S3OriginConfig': {
                            'OriginAccessIdentity': ''
                        },
                        'OriginAccessControlId': oac_id
                    }
                ]
            },
            'DefaultCacheBehavior': {
                'TargetOriginId': f'{bucket_name}-origin',
                'ViewerProtocolPolicy': 'redirect-to-https',
                'TrustedSigners': {
                    'Enabled': False,
                    'Quantity': 0
                },
                'ForwardedValues': {
                    'QueryString': False,
                    'Cookies': {
                        'Forward': 'none'
                    }
                },
                'MinTTL': 0,
                'DefaultTTL': 86400,
                'MaxTTL': 31536000
            },
            'Enabled': True,
            'PriceClass': 'PriceClass_100'
        }
        
        try:
            distribution_response = cloudfront.create_distribution(
                DistributionConfig=distribution_config
            )
            distribution_id = distribution_response['Distribution']['Id']
            domain_name = distribution_response['Distribution']['DomainName']
            print(f"✅ Created CloudFront distribution: {distribution_id}")
            print(f"🌐 Domain name: {domain_name}")
        except Exception as e:
            print(f"❌ Error creating distribution: {e}")
            return None
        
        # Step 3: Update S3 bucket policy to allow CloudFront OAC access
        print("🔒 Updating S3 bucket policy for OAC access...")
        
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowCloudFrontServicePrincipal",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudfront.amazonaws.com"
                    },
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    "Condition": {
                        "StringEquals": {
                            "AWS:SourceArn": f"arn:aws:cloudfront::962265335633:distribution/{distribution_id}"
                        }
                    }
                }
            ]
        }
        
        s3.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(bucket_policy)
        )
        
        print("✅ S3 bucket policy updated successfully")
        
        # Wait for distribution to be deployed
        print("⏳ Waiting for CloudFront distribution to be deployed...")
        waiter = cloudfront.get_waiter('distribution_deployed')
        waiter.wait(Id=distribution_id, WaiterConfig={'Delay': 30, 'MaxAttempts': 40})
        
        print("✅ CloudFront distribution deployed successfully!")
        
        return {
            'distribution_id': distribution_id,
            'domain_name': domain_name,
            'oac_id': oac_id,
            'image_url': f'https://{domain_name}/architecture-diagram.png'
        }
        
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        return None

if __name__ == "__main__":
    result = setup_cloudfront_s3()
    if result:
        print(f"\n🎉 Setup completed successfully!")
        print(f"📊 Image URL: {result['image_url']}")
        
        # Save configuration
        with open('cloudfront_config.json', 'w') as f:
            json.dump(result, f, indent=2)
        print(f"📄 Configuration saved to: cloudfront_config.json")