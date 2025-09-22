#!/usr/bin/env python3
"""
DPoP (Demonstrating Proof-of-Possession) MVP Demo Script
=========================================================

This script demonstrates the OAuth2 DPoP extension RFC 9449, which prevents
token theft and replay attacks by cryptographically binding access tokens
to client keys.

DPoP Overview:
--------------
DPoP (Demonstrating Proof-of-Possession) is an OAuth2 extension that binds
access tokens to a cryptographic key pair held by the client. This prevents
tokens from being used by attackers even if they are stolen, because the
attacker would also need the private key to generate valid DPoP proofs.

Architecture:
-------------
1. Identity Provider (IdP) - Issues DPoP-bound access tokens
2. Resource Server - Validates tokens and DPoP proofs  
3. Client - Holds mTLS certificates and DPoP key pair

Security Flow:
--------------
1. Client authenticates to IdP using mTLS (mutual TLS)
2. Client creates ephemeral DPoP key pair (EC P-256)
3. Client sends DPoP proof JWT with token request
4. IdP issues access token bound to DPoP public key
5. For each resource request, client creates fresh DPoP proof
6. Resource server validates both token and DPoP proof

Key Security Properties:
------------------------
- Token binding: Tokens only work with the DPoP private key
- Replay protection: Each DPoP proof includes unique 'jti' (JWT ID)
- Freshness: DPoP proofs include current timestamp
- Request binding: DPoP proof tied to specific HTTP method and URL

Dependencies:
-------------
pip install requests jwcrypto

Usage:
------
python dpop_demo.py <cert_dir> <idp_url> <resource_url>

Example:
--------
python dpop_demo.py ./certs https://idp.example.com https://api.example.com/verify

Author: Generated for DPoP demonstration purposes
License: MIT
"""

import json
import time
import uuid
import base64
import hashlib
import requests
from jwcrypto import jwk, jwt


class DPoPDemo:
    """
    DPoP (Demonstrating Proof-of-Possession) demonstration client.
    
    This class implements a minimal OAuth2 + DPoP flow:
    1. Authenticate to IdP using mTLS
    2. Request DPoP-bound access token
    3. Access protected resource with DPoP proof
    
    Attributes:
        idp_url (str): Identity Provider base URL (e.g., https://idp.example.com)
        resource_url (str): Protected resource URL (e.g., https://api.example.com/data)
        client_cert (str): Path to client certificate for mTLS authentication
        client_key (str): Path to client private key for mTLS authentication
    """
    
    def __init__(self, client_cert_dir, idp_url="https://localhost:8080", resource_url="https://localhost:8081"):
        """
        Initialize DPoP demo client with certificate paths and server URLs.
        
        Args:
            client_cert_dir (str): Directory containing client.crt and client.key files
            idp_url (str, optional): Identity Provider URL. Defaults to "https://localhost:8080"
            resource_url (str, optional): Resource server URL. Defaults to "https://localhost:8081"
        
        Note:
            The client_cert_dir must contain:
            - client.crt: Client certificate for mTLS authentication
            - client.key: Client private key for mTLS authentication
        """
        self.idp_url = idp_url.rstrip('/')
        self.resource_url = resource_url.rstrip('/')
        self.client_cert = f"{client_cert_dir}/client.crt"
        self.client_key = f"{client_cert_dir}/client.key"
        
    def create_dpop_key(self):
        """
        Create an ephemeral EC P-256 key pair for DPoP proof generation.
        
        DPoP uses ephemeral keys (created fresh for each session) rather than
        long-term keys. This limits the impact if a key is compromised and
        enables better key rotation practices.
        
        The key pair consists of:
        - Private key: Used to sign DPoP proofs (kept secret by client)
        - Public key: Included in DPoP proofs for verification (public)
        
        Returns:
            tuple: (private_key, public_key) as jwcrypto.jwk.JWK objects
            
        Note:
            EC P-256 is chosen because:
            - Smaller signatures than RSA
            - Good security properties
            - Widely supported
            - Required by DPoP spec
        """
        print("🔑 Creating ephemeral EC P-256 key pair for DPoP...")
        
        # Generate EC P-256 private key
        private_key = jwk.JWK.generate(kty="EC", crv="P-256")
        
        # Extract corresponding public key
        public_key = jwk.JWK()
        public_key.import_key(**json.loads(private_key.export_public()))
        
        print("   ✅ DPoP key pair created successfully")
        return private_key, public_key
    
    def create_dpop_proof(self, private_key, method, url, access_token=None):
        """
        Create a DPoP proof JWT for the given request.
        
        A DPoP proof is a JWT that demonstrates possession of the private key
        associated with a DPoP-bound access token. Each proof is unique and
        tied to a specific HTTP request.
        
        Args:
            private_key (jwk.JWK): DPoP private key for signing
            method (str): HTTP method (GET, POST, etc.)
            url (str): Full URL being accessed
            access_token (str, optional): Access token to bind proof to
        
        Returns:
            str: Signed DPoP proof JWT
            
        DPoP Proof Structure:
        ---------------------
        Header:
        - typ: "dpop+jwt" (identifies this as DPoP proof)
        - alg: "ES256" (ECDSA with SHA-256)
        - jwk: Public key for verification
        
        Claims:
        - htm: HTTP method (uppercase)
        - htu: HTTP URL (the target endpoint)
        - jti: Unique identifier (prevents replay)
        - iat: Issued at timestamp (freshness)
        - ath: Access token hash (if using token)
        
        Security Notes:
        ---------------
        - Each proof MUST be unique (different jti)
        - Proofs MUST be fresh (current iat)
        - Proofs are tied to specific requests (htm + htu)
        - Token binding prevents token misuse (ath)
        """
        # Extract public key for inclusion in proof
        public_key = jwk.JWK()
        public_key.import_key(**json.loads(private_key.export_public()))
        
        # DPoP proof header - identifies this as a DPoP proof JWT
        header = {
            "typ": "dpop+jwt",           # Required DPoP type identifier
            "alg": "ES256",              # ECDSA with SHA-256 signature
            "jwk": json.loads(public_key.export_public())  # Public key for verification
        }
        
        # DPoP proof claims - bind proof to specific request
        claims = {
            "htm": method.upper(),       # HTTP method (MUST be uppercase)
            "htu": url,                  # HTTP URL (full target URL)
            "jti": str(uuid.uuid4()),    # Unique ID (prevents replay attacks)
            "iat": int(time.time())      # Issued at (current timestamp)
        }
        
        # Include access token hash if we're using a token
        # This cryptographically binds the proof to the specific token
        if access_token:
            # SHA-256 hash of the access token, base64url encoded
            token_hash = hashlib.sha256(access_token.encode()).digest()
            claims["ath"] = base64.urlsafe_b64encode(token_hash).rstrip(b"=").decode()
            print(f"   🔗 Binding proof to access token (ath: {claims['ath'][:16]}...)")
        
        # Create and sign the JWT
        proof = jwt.JWT(header=header, claims=claims)
        proof.make_signed_token(private_key)
        
        print(f"   📝 Created DPoP proof for {method} {url}")
        print(f"   🆔 Proof ID (jti): {claims['jti']}")
        
        return proof.serialize()
    
    def get_access_token(self, dpop_key):
        """
        Request a DPoP-bound access token from the Identity Provider.
        
        This implements the OAuth2 Client Credentials flow with DPoP extension:
        1. Authenticate using mTLS (client certificate)
        2. Include DPoP proof in request
        3. Receive access token bound to DPoP public key
        
        Args:
            dpop_key (jwk.JWK): DPoP private key for signing proof
            
        Returns:
            str: DPoP-bound access token
            
        OAuth2 Client Credentials with DPoP:
        -------------------------------------
        POST /oauth/token
        Headers:
        - DPoP: [DPoP proof JWT]
        - Content-Type: application/x-www-form-urlencoded
        
        Body:
        - grant_type=client_credentials
        - scope=read write
        
        mTLS Authentication:
        --------------------
        The client certificate is used for authentication, proving the
        client's identity to the IdP. This is more secure than client
        secrets as certificates can't be easily stolen from code.
        
        Response:
        ---------
        {
          "access_token": "...",
          "token_type": "DPoP",
          "expires_in": 3600,
          "scope": "read write"
        }
        """
        print("🎫 Requesting DPoP-bound access token from IdP...")
        
        # Construct token endpoint URL
        token_url = f"{self.idp_url}/oauth/token"
        print(f"   🎯 Token endpoint: {token_url}")
        
        # Create DPoP proof for the token request
        # This proves we hold the private key we want to bind the token to
        print("   📝 Creating DPoP proof for token request...")
        dpop_proof = self.create_dpop_proof(dpop_key, "POST", token_url)
        
        # Prepare request headers
        headers = {
            "DPoP": dpop_proof,                                    # DPoP proof JWT
            "Content-Type": "application/x-www-form-urlencoded"    # OAuth2 standard
        }
        
        # Prepare request body (OAuth2 Client Credentials flow)
        data = {
            "grant_type": "client_credentials",    # We're a confidential client
            "scope": "read write"                  # Requested permissions
        }
        
        print("   🔐 Authenticating with mTLS certificate...")
        print(f"   📜 Using certificate: {self.client_cert}")
        
        # Make token request with mTLS authentication
        response = requests.post(
            token_url, 
            headers=headers, 
            data=data, 
            cert=(self.client_cert, self.client_key),  # mTLS authentication
            verify=True  # Skip cert verification for demo (don't do this in production!)
        )
        
        # Parse token response
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data["access_token"]
            
            print("   ✅ Access token received successfully!")
            print(f"   🎫 Token type: {token_data.get('token_type', 'unknown')}")
            print(f"   ⏰ Expires in: {token_data.get('expires_in', 'unknown')} seconds")
            print(f"   🔒 Scopes: {token_data.get('scope', 'unknown')}")
            print(f"   🔑 Token preview: {access_token[:20]}...")
            
            return access_token
        else:
            print(f"   ❌ Token request failed: HTTP {response.status_code}")
            print(f"   📄 Error response: {response.text}")
            raise Exception(f"Token request failed: {response.status_code}")
    
    def call_protected_resource(self, access_token, dpop_key, endpoint=""):
        """
        Call a protected resource using the DPoP-bound access token.
        
        This demonstrates how DPoP-bound tokens are used to access protected
        resources. Each request must include:
        1. Authorization header with DPoP token
        2. Fresh DPoP proof for this specific request
        
        Args:
            access_token (str): DPoP-bound access token from IdP
            dpop_key (jwk.JWK): DPoP private key (same as used for token request)
            endpoint (str, optional): Additional path to append to resource URL
            
        Returns:
            requests.Response: HTTP response from resource server
            
        DPoP Resource Access:
        ---------------------
        GET /protected-resource
        Headers:
        - Authorization: DPoP [access_token]
        - DPoP: [fresh DPoP proof JWT]
        
        Security Validation by Resource Server:
        ---------------------------------------
        1. Verify access token signature and claims
        2. Extract DPoP public key from token's 'cnf' claim
        3. Verify DPoP proof signature using public key
        4. Validate DPoP proof claims (htm, htu, jti, iat, ath)
        5. Check that proof's 'ath' matches token hash
        6. Ensure proof is fresh and not replayed
        
        Why This Is Secure:
        -------------------
        - Token theft useless without private key
        - Each request needs fresh DPoP proof
        - Proofs are tied to specific requests
        - Replay attacks prevented by jti uniqueness
        """
        # Use the full resource URL as provided, don't append anything if endpoint is empty
        full_resource_url = f"{self.resource_url}{endpoint}" if endpoint else self.resource_url
        print(f"🌐 Calling protected resource: {full_resource_url}")
        
        # Create fresh DPoP proof for this specific request
        # This proof binds the access token to this exact HTTP request
        print("   📝 Creating fresh DPoP proof for resource access...")
        dpop_proof = self.create_dpop_proof(dpop_key, "GET", full_resource_url, access_token)
        
        # Prepare request headers for DPoP authentication
        headers = {
            "Authorization": f"DPoP {access_token}",  # DPoP token type with access token
            "DPoP": dpop_proof                        # Fresh DPoP proof for this request
        }
        
        print("   🚀 Sending authenticated request to resource server...")
        
        # Make request to protected resource
        # Note: We also use mTLS here, but the main authentication is via DPoP token
        response = requests.get(
            full_resource_url, 
            headers=headers, 
            cert=(self.client_cert, self.client_key),  # Optional: mTLS to resource server
            verify=True  # Skip cert verification for demo
        )
        
        # Display response details
        print(f"   📊 Response Status: {response.status_code}")
        if response.text:
            # Truncate long responses for readability
            body_preview = response.text[:200]
            if len(response.text) > 200:
                body_preview += "..."
            print(f"   📄 Response Body: {body_preview}")
        
        return response
    
    def run_demo(self):
        """
        Execute the complete DPoP demonstration workflow.
        
        This method orchestrates the entire DPoP flow:
        1. Create ephemeral DPoP key pair
        2. Request DPoP-bound access token (with mTLS auth)
        3. Access protected resource (with DPoP proof)
        
        The demo shows how DPoP prevents token theft and replay attacks
        by requiring cryptographic proof of key possession for each request.
        
        Workflow Details:
        -----------------
        Step 1: Key Generation
        - Create fresh EC P-256 key pair for this session
        - Private key stays with client, public key shared in proofs
        
        Step 2: Token Request
        - Authenticate to IdP using mTLS (client certificate)
        - Send DPoP proof demonstrating key possession
        - Receive access token bound to DPoP public key
        
        Step 3: Resource Access
        - Create fresh DPoP proof for specific resource request
        - Send token + proof to resource server
        - Resource server validates both token and proof
        
        Security Benefits Demonstrated:
        -------------------------------
        - Token binding: Stolen tokens are useless without private key
        - Request freshness: Each request needs a new proof
        - Replay protection: Unique identifiers prevent reuse
        - Request specificity: Proofs tied to exact HTTP method and URL
        """
        print("🚀 DPoP MVP Demo - Demonstrating Proof-of-Possession")
        print("=" * 60)
        print()
        print("📋 DPoP Security Flow Overview:")
        print("   1. Create ephemeral key pair for token binding")
        print("   2. Request DPoP-bound token using mTLS + DPoP proof") 
        print("   3. Access resource with token + fresh DPoP proof")
        print("   4. Each request requires new proof → prevents replay")
        print("   5. Token bound to key → prevents theft")
        print()
        
        try:
            # Step 1: Create DPoP key pair
            print("1️⃣  STEP 1: Creating DPoP Key Pair")
            print("-" * 40)
            dpop_private_key, dpop_public_key = self.create_dpop_key()
            print(f"   📁 Using mTLS cert: {self.client_cert}")
            print("   🔒 Key pair created - ready for token binding")
            print()
            
            # Step 2: Get access token bound to DPoP key (authenticated via mTLS)
            print("2️⃣  STEP 2: Getting DPoP-Bound Access Token")
            print("-" * 40)
            print("   🔐 This step demonstrates:")
            print("   • Client authentication via mTLS certificate")
            print("   • DPoP proof creation and transmission")
            print("   • Token binding to DPoP public key")
            print()
            access_token = self.get_access_token(dpop_private_key)
            print("   🎯 Token is now cryptographically bound to our DPoP key")
            print()
            
            # Step 3: Use token with DPoP proof to access protected resource
            print("3️⃣  STEP 3: Accessing Protected Resource")
            print("-" * 40)
            print("   🛡️  This step demonstrates:")
            print("   • Fresh DPoP proof generation for each request")
            print("   • Token and proof validation by resource server")
            print("   • Prevention of token theft and replay attacks")
            print()
            print(f"   🎯 Resource server: {self.resource_url}")
            response = self.call_protected_resource(access_token, dpop_private_key)
            
            # Evaluate results
            print()
            print("4️⃣  STEP 4: Results Analysis")
            print("-" * 40)
            if response and response.status_code == 200:
                print("🎉 Demo completed successfully!")
                print()
                print("✅ Security benefits achieved:")
                print("   • Token bound to cryptographic key (prevents theft)")
                print("   • Fresh proof per request (prevents replay)")
                print("   • Request-specific binding (prevents misuse)")
                print("   • mTLS authentication (strong client identity)")
            elif response and response.status_code == 401:
                print("🔒 Access denied (HTTP 401) - This could indicate:")
                print("   • Token expired or invalid")
                print("   • DPoP proof verification failed") 
                print("   • Missing or incorrect authorization header")
            elif response and response.status_code == 403:
                print("🚫 Forbidden (HTTP 403) - This could indicate:")
                print("   • Valid token but insufficient permissions")
                print("   • DPoP binding validation failed")
            elif response and response.status_code == 404:
                print("❓ Resource not found (HTTP 404)")
                print("   • Check if the resource URL is correct")
                print("   • Verify the resource server is running")
            else:
                print(f"❌ Unexpected response: HTTP {response.status_code if response else 'No response'}")
                print("   • Check server logs for detailed error information")
            
        except Exception as e:
            print()
            print("💥 Demo failed with error:")
            print(f"   {str(e)}")
            print()
            print("🔍 Common issues:")
            print("   • Certificate files not found or invalid")
            print("   • IdP server not reachable or misconfigured")
            print("   • Network connectivity issues")
            print("   • Invalid DPoP implementation on server side")


def main():
    """
    Main entry point for the DPoP demonstration script.
    
    This function handles command-line arguments and initializes the demo.
    
    Command Line Usage:
    -------------------
    python dpop_demo.py <cert_dir> [idp_url] [resource_url]
    
    Arguments:
    ----------
    cert_dir: Directory containing client.crt and client.key for mTLS
    idp_url: Identity Provider URL (optional, defaults to localhost:8080)
    resource_url: Protected resource URL (optional, defaults to localhost:8081)
    
    Examples:
    ---------
    # Local development with default URLs
    python dpop_demo.py ./certs
    
    # Production servers
    python dpop_demo.py ./certs https://idp.example.com https://api.example.com/data
    
    # Mixed local/remote setup
    python dpop_demo.py ./certs https://idp.example.com https://localhost:8081/api
    
    Certificate Requirements:
    -------------------------
    The certificate directory must contain:
    - client.crt: X.509 client certificate for mTLS authentication
    - client.key: Private key corresponding to client certificate
    
    Both files should be in PEM format and the certificate should be
    trusted by the IdP for client authentication.
    
    Security Notes:
    ---------------
    - This demo disables certificate verification (verify=False) for
      testing with self-signed certificates. In production, always
      verify server certificates to prevent man-in-the-middle attacks.
    - Client certificates should be kept secure and rotated regularly
    - DPoP keys are ephemeral and created fresh for each session
    """
    import sys
    
    # Display usage information if insufficient arguments
    if len(sys.argv) < 2:
        print("DPoP (Demonstrating Proof-of-Possession) Demo Script")
        print("=" * 55)
        print()
        print("USAGE:")
        print("  python dpop_demo.py <cert_dir> [idp_url] [resource_url]")
        print()
        print("ARGUMENTS:")
        print("  cert_dir     Directory containing client.crt and client.key")
        print("  idp_url      Identity Provider URL (default: https://localhost:8080)")
        print("  resource_url Protected resource URL (default: https://localhost:8081)")
        print()
        print("EXAMPLES:")
        print("  # Local development")
        print("  python dpop_demo.py ./certs")
        print()
        print("  # Production servers")
        print("  python dpop_demo.py ./certs https://idp.example.com https://api.example.com")
        print()
        print("  # Your specific setup")
        print("  python dpop_demo.py ~/certs/mtls https://idp.madmetal.org https://api.madmetal.org/verify")
        print()
        print("REQUIREMENTS:")
        print("  - Client certificate (client.crt) and key (client.key) in cert_dir")
        print("  - Python packages: requests, jwcrypto")
        print("  - Network access to IdP and resource server")
        sys.exit(1)
    
    # Parse command line arguments
    client_cert_dir = sys.argv[1]
    idp_url = sys.argv[2] if len(sys.argv) > 2 else "https://localhost:8080"
    resource_url = sys.argv[3] if len(sys.argv) > 3 else "https://localhost:8081"
    
    # Display configuration
    print("🔧 DPoP Demo Configuration")
    print("=" * 30)
    print(f"🔗 IdP Server: {idp_url}")
    print(f"🎯 Resource Server: {resource_url}")
    print(f"📁 Client Certs: {client_cert_dir}")
    print()
    
    # Initialize and run demo
    demo = DPoPDemo(client_cert_dir, idp_url, resource_url)
    demo.run_demo()


if __name__ == "__main__":
    main()
