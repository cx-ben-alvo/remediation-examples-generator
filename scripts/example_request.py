#!/usr/bin/env python3
"""
Example script showing how to use the Code Remediation API.
"""

import asyncio
import httpx
import json

async def test_remediation_api():
    """Test the remediation API with the example from the requirements."""
    
    # Example request from the requirements
    request_data = {
        "language": "go",
        "ruleName": "Unsafe SQL Query Construction",
        "description": "Dynamically constructing SQL queries through string concatenation can lead to SQL injection vulnerabilities, allowing attackers to manipulate queries and execute arbitrary commands. Properly handling user input and using parameterized queries are essential to prevent unauthorized data access and protect against data breaches",
        "remediationAdvice": "Consider using parameterized queries with SqlCommand and not concatenate strings to form SQL queries."
    }
    
    print("🚀 Testing Code Remediation API")
    print("=" * 50)
    print(f"Request:")
    print(json.dumps(request_data, indent=2))
    print("=" * 50)
    
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                "http://localhost:8000/api/remediation",
                json=request_data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                print("✅ API Response (Success):")
                print(json.dumps(result, indent=2))
                return True
            else:
                print(f"❌ API Error (Status {response.status_code}):")
                try:
                    error_detail = response.json()
                    print(json.dumps(error_detail, indent=2))
                except:
                    print(response.text)
                return False
                
    except httpx.ConnectError:
        print("❌ Connection failed - make sure the API server is running at http://localhost:8000")
        print("   Start the server with: python main.py")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

async def test_health_endpoint():
    """Test the health check endpoint."""
    print("\n🔍 Testing health endpoint...")
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get("http://localhost:8000/health")
            
            if response.status_code == 200:
                result = response.json()
                print("✅ Health check passed:")
                print(json.dumps(result, indent=2))
                return True
            else:
                print(f"❌ Health check failed (Status {response.status_code})")
                return False
                
    except httpx.ConnectError:
        print("❌ Connection failed - server not running")
        return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

async def main():
    """Run the API tests."""
    print("📡 Code Remediation API Test Suite")
    print("=" * 60)
    
    # Test health endpoint first
    health_ok = await test_health_endpoint()
    
    if not health_ok:
        print("\n❌ Health check failed. Please start the server first:")
        print("   python main.py")
        return 1
    
    # Test the main remediation endpoint
    remediation_ok = await test_remediation_api()
    
    print("\n" + "=" * 60)
    if health_ok and remediation_ok:
        print("🎉 All API tests passed successfully!")
        return 0
    else:
        print("⚠️  Some tests failed. Check the server logs.")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code) 