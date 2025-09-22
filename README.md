# mTLS DPoP Demo

Simple demo of Identity Provider mTLS authentication + DPoP resource server authentication using OAuth2 DPoP extension (RFC 9449).

## Overview

This demonstration shows how DPoP (Demonstrating Proof-of-Possession) prevents token theft and replay attacks by cryptographically binding OAuth2 access tokens to client keys. The demo combines mTLS client authentication with DPoP token binding for enhanced security.

### Security Flow

1. **Client Authentication**: Client authenticates to Identity Provider using mTLS (mutual TLS)
2. **DPoP Key Generation**: Client creates ephemeral EC P-256 key pair
3. **Token Request**: Client sends DPoP proof JWT with OAuth2 token request
4. **Token Binding**: IdP issues access token bound to DPoP public key
5. **Resource Access**: For each resource request, client creates fresh DPoP proof
6. **Validation**: Resource server validates both token and DPoP proof

## Prerequisites

- Python 3.7 or higher
- Client certificate and private key for mTLS authentication
- Network access to Identity Provider and Resource Server

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/larshansen1/mtls_dpop_demo.git
cd mtls_dpop_demo
```

### 2. Setup Virtual Environment

#### Unix/Linux/macOS

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

#### Windows

```cmd
# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Command Line Syntax

```bash
python demo_cli.py <cert_dir> [idp_url] [resource_url]
```

### Parameters

- `cert_dir`: Directory containing client.crt and client.key files
- `idp_url`: Identity Provider URL (optional, defaults to https://localhost:8080)
- `resource_url`: Protected resource URL (optional, defaults to https://localhost:8081)

### Certificate Directory Structure

Your certificate directory must contain:
- `client.crt`: X.509 client certificate in PEM format
- `client.key`: Private key corresponding to client certificate in PEM format

### Example Usage

#### Unix/Linux/macOS Examples

```bash
# Local development with default URLs
python demo_cli.py ./certs

# Using relative path with custom servers
python demo_cli.py ../certificates https://idp.example.org https://resource.example.org

# Using absolute path
python demo_cli.py /home/user/certificates https://idp.example.org https://resource.example.org/api
```

#### Windows Examples

```cmd
# Local development with default URLs
python demo_cli.py .\certs

# Using relative path with custom servers
python demo_cli.py ..\certificates https://idp.example.org https://resource.example.org

# Using absolute path
python demo_cli.py C:\Users\username\certificates https://idp.example.org https://resource.example.org\api
```

### Production Example

```bash
# Complete production setup
python demo_cli.py ./production-certs https://idp.example.org https://resource.example.org
```

## Certificate Setup

### Certificate Requirements

1. **Client Certificate** (`client.crt`):
   - Must be in PEM format
   - Should be signed by a CA trusted by the Identity Provider
   - Used for mTLS client authentication

2. **Private Key** (`client.key`):
   - Must correspond to the client certificate
   - Should be in PEM format
   - Keep secure and never share

### Example Certificate Directory

```
certs/
├── client.crt    # Client certificate for mTLS
└── client.key    # Private key for client certificate
```

## Security Features

### DPoP Benefits

- **Token Binding**: Access tokens are cryptographically bound to client keys
- **Replay Protection**: Each request requires a unique DPoP proof
- **Theft Prevention**: Stolen tokens are useless without the private key
- **Request Specificity**: Proofs are tied to specific HTTP methods and URLs

### mTLS Benefits

- **Strong Authentication**: Client identity verified through certificates
- **Mutual Authentication**: Both client and server verify each other
- **Certificate-based Security**: More secure than shared secrets

## Troubleshooting

### Common Issues

1. **Certificate Not Found**
   - Verify certificate files exist in specified directory
   - Check file permissions (readable by current user)
   - Ensure filenames are exactly `client.crt` and `client.key`

2. **Connection Failed**
   - Verify server URLs are accessible
   - Check network connectivity
   - Confirm servers are running and configured properly

3. **Authentication Failed**
   - Ensure client certificate is trusted by the IdP
   - Verify certificate has not expired
   - Check that private key matches certificate

4. **DPoP Validation Failed**
   - Confirm resource server supports DPoP
   - Verify system clock is synchronized (for timestamp validation)
   - Check server logs for specific DPoP errors

### Debug Mode

For additional debug information, you can modify the script to enable verbose logging or add print statements to track the authentication flow.

## Dependencies

The demo requires the following Python packages:

- `requests`: HTTP client library
- `jwcrypto`: JSON Web Key and JSON Web Token handling

These are automatically installed when running `pip install -r requirements.txt`.

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Security Notes

- This demo disables SSL certificate verification for development purposes
- In production, always verify server certificates
- Keep client certificates and private keys secure
- Rotate certificates regularly
- Monitor for certificate expiration

## References

- [RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)](https://tools.ietf.org/rfc/rfc9449.html)
- [RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://tools.ietf.org/rfc/rfc8705.html)
