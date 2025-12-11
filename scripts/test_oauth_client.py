#!/usr/bin/env python3
"""
Test OAuth2 client credentials against OryxID backend.

Usage:
    python test_oauth_client.py --client-id <id> --client-secret <secret>
    python test_oauth_client.py -c <id> -s <secret> --url http://localhost:9000
"""

import argparse
import sys
import json
import urllib.request
import urllib.parse
import urllib.error


def test_client_credentials(base_url: str, client_id: str, client_secret: str, scope: str = "read") -> dict:
    """Test client credentials grant flow."""
    token_url = f"{base_url.rstrip('/')}/oauth/token"

    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
    }).encode("utf-8")

    request = urllib.request.Request(
        token_url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = json.loads(response.read().decode("utf-8"))
            return {"success": True, "status": response.status, "body": body}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            pass
        return {"success": False, "status": e.code, "error": str(e.reason), "body": body}
    except urllib.error.URLError as e:
        return {"success": False, "status": None, "error": str(e.reason), "body": None}
    except Exception as e:
        return {"success": False, "status": None, "error": str(e), "body": None}


def test_token_introspection(base_url: str, client_id: str, client_secret: str, token: str) -> dict:
    """Test token introspection endpoint."""
    introspect_url = f"{base_url.rstrip('/')}/oauth/introspect"

    data = urllib.parse.urlencode({"token": token}).encode("utf-8")

    # Basic auth
    import base64
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

    request = urllib.request.Request(
        introspect_url,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {credentials}"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = json.loads(response.read().decode("utf-8"))
            return {"success": True, "status": response.status, "body": body}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            pass
        return {"success": False, "status": e.code, "error": str(e.reason), "body": body}
    except Exception as e:
        return {"success": False, "status": None, "error": str(e), "body": None}


def main():
    parser = argparse.ArgumentParser(description="Test OAuth2 client credentials")
    parser.add_argument("-c", "--client-id", required=True, help="OAuth client ID")
    parser.add_argument("-s", "--client-secret", required=True, help="OAuth client secret")
    parser.add_argument("-u", "--url", default="http://localhost:9000", help="Backend URL")
    parser.add_argument("--scope", default="read", help="Requested scope")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    print(f"Testing OAuth client credentials against {args.url}")
    print(f"Client ID: {args.client_id}")
    print("-" * 50)

    # Test 1: Client credentials grant
    print("\n[1] Testing client_credentials grant...")
    result = test_client_credentials(args.url, args.client_id, args.client_secret, args.scope)

    if result["success"]:
        print("    Status: SUCCESS")
        print(f"    Access Token: {result['body'].get('access_token', 'N/A')[:50]}...")
        print(f"    Token Type: {result['body'].get('token_type', 'N/A')}")
        print(f"    Expires In: {result['body'].get('expires_in', 'N/A')} seconds")
        print(f"    Scope: {result['body'].get('scope', 'N/A')}")

        access_token = result["body"].get("access_token")

        # Test 2: Token introspection
        if access_token:
            print("\n[2] Testing token introspection...")
            intro_result = test_token_introspection(
                args.url, args.client_id, args.client_secret, access_token
            )

            if intro_result["success"]:
                print("    Status: SUCCESS")
                print(f"    Active: {intro_result['body'].get('active', 'N/A')}")
                print(f"    Client ID: {intro_result['body'].get('client_id', 'N/A')}")
                print(f"    Scope: {intro_result['body'].get('scope', 'N/A')}")
            else:
                print(f"    Status: FAILED ({intro_result.get('status', 'N/A')})")
                print(f"    Error: {intro_result.get('error', 'Unknown')}")

        print("\n" + "=" * 50)
        print("RESULT: Client credentials are VALID")
        print("=" * 50)
        return 0
    else:
        print(f"    Status: FAILED ({result.get('status', 'N/A')})")
        print(f"    Error: {result.get('error', 'Unknown')}")
        if args.verbose and result.get("body"):
            print(f"    Response: {json.dumps(result['body'], indent=2)}")

        print("\n" + "=" * 50)
        print("RESULT: Client credentials are INVALID")
        print("=" * 50)
        return 1


if __name__ == "__main__":
    sys.exit(main())
