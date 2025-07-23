# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Quality Assurance
- `composer checks` - Run all checks (code style, static analysis, tests)
- `composer cs` - Run code style checker (phpcs)
- `composer csfix` - Auto-fix code style issues (phpcbf)
- `composer phpstan` - Run static analysis
- `composer tests` - Run PHPUnit test suite

### Test Execution
- `vendor/bin/phpunit` - Run all tests
- `vendor/bin/phpunit tests/Specific/TestFile.php` - Run specific test file
- `vendor/bin/phpunit --filter testMethodName` - Run specific test method
- `vendor/bin/phpunit --no-coverage` - Run tests without coverage (faster)

## Architecture Overview

This is a modern PHP 8.4+ OpenID Connect implementation built on Symfony contracts with a factory-based architecture.

### Core Architecture Pattern
The library uses a **Factory → Facade → Specialized Services** pattern:

1. **OidcFactory** - Central factory that creates configured OIDC clients
   - Takes HttpClientInterface and optional CacheInterface
   - Supports configurable cache secret for HMAC-based cache keys
   - Supports both discovery (from issuer URL) and manual configuration
   - Returns an `Oidc` facade instance

2. **Oidc** - Main facade providing access to three core flows:
   - `authorizationCode()` - Authorization Code flow for web apps
   - `clientCredentials()` - Client Credentials flow for server-to-server
   - `resourceServer()` - Token validation for resource servers

### Key Architectural Components

**Configuration Layer** (`src/Config/`):
- `ClientMetadata` - OAuth2/OIDC client configuration
- `IssuerMetadata` - Provider/issuer metadata
- `Config` - Base configuration interface with two implementations:
  - `DiscoveryConfig` - Dynamic configuration using OIDC discovery
  - `StaticConfig` - Manual configuration without discovery

**Discovery Layer** (`src/Discovery/`):
- `HttpDiscoverer` - Fetches OIDC discovery documents
- `HttpJwksLoader` - Loads JSON Web Key Sets (JWKS)
- `CachingDiscoverer` and `CachingJwksLoader` - Caching decorators

**Client Layer** (`src/Client/`):
- `AuthorizationCode` - Handles authorization code flow
- `ClientCredentials` - Handles client credentials flow
- `JwtIdTokenValidator` - Validates ID tokens using JWT
- `Tokens` - Token container with access/ID/refresh tokens

**Resource Server Layer** (`src/ResourceServer/`):
- `ResourceServer` - Main entry point for token validation
- Token validators supporting both JWT and opaque tokens:
  - `JwtAccessTokenValidator` - For JWT access tokens
  - `OpaqueAccessTokenValidator` - For opaque tokens (introspection)
- `CachingAccessTokenValidator` - Caching decorator with HMAC-based cache keys for security

### Security Features
- **HMAC-based cache keys** - `CachingAccessTokenValidator` uses HMAC with configurable secrets to prevent timing attacks
- **JWT validation** - Full signature and claims validation using web-token/jwt-library
- **PKCE support** - Built-in Proof Key for Code Exchange implementation
- **Configurable authentication methods** - Support for client_secret_basic, client_secret_post, and none

### Testing Architecture
- `TestCase` base class provides JWT testing utilities
- Comprehensive test coverage across all components
- Security-focused testing including cache timing attack prevention
- Mock-friendly architecture with dependency injection

### Dependency Requirements
- PHP 8.4+
- Symfony HTTP Client contracts (not tied to specific Symfony version)
- Symfony Cache contracts for optional caching
- web-token/jwt-library for JWT operations