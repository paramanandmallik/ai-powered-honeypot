#!/usr/bin/env python3
"""
Test script to verify S3 image accessibility and dashboard integration
"""

import requests
import json

def test_s3_image():
    """Test if the S3 image is accessible"""
    image_url = "https://d3nswgo2anpzyz.cloudfront.net/architecture-diagram.png"
    
    try:
        response = requests.head(image_url, timeout=10)
        print(f"✅ S3 Image Status: {response.status_code}")
        print(f"✅ Content Type: {response.headers.get('content-type', 'Unknown')}")
        print(f"✅ Content Length: {response.headers.get('content-length', 'Unknown')} bytes")
        return True
    except Exception as e:
        print(f"❌ S3 Image Error: {e}")
        return False

def test_dashboard_endpoint():
    """Test if the dashboard endpoint is working"""
    dashboard_url = "https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod/"
    
    try:
        response = requests.get(dashboard_url, timeout=10)
        print(f"✅ Dashboard Status: {response.status_code}")
        
        # Check if the S3 image URL is in the response
        if "d3nswgo2anpzyz.cloudfront.net/architecture-diagram.png" in response.text:
            print("✅ S3 Image URL found in dashboard HTML")
        else:
            print("❌ S3 Image URL NOT found in dashboard HTML")
            
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Dashboard Error: {e}")
        return False

if __name__ == "__main__":
    print("🔍 Testing S3 Image and Dashboard Integration...")
    print("=" * 50)
    
    s3_ok = test_s3_image()
    print()
    dashboard_ok = test_dashboard_endpoint()
    
    print("\n" + "=" * 50)
    if s3_ok and dashboard_ok:
        print("✅ All tests passed! S3 image should be visible in dashboard.")
    else:
        print("❌ Some tests failed. Check the issues above.")
    
    print("\n🌐 Dashboard URL: https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod/")
    print("🖼️  S3 Image URL: https://d3nswgo2anpzyz.cloudfront.net/architecture-diagram.png")