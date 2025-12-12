# GitHub Copilot Instructions

This document provides guidance to GitHub Copilot coding agent when working on this repository.

## Project Overview

This is a modern PHP 8.4+ OpenID Connect (OIDC) implementation built on Symfony contracts. The library provides a clean, well-tested API for implementing OAuth2/OIDC flows in PHP applications.

**Key Features:**
- Authorization Code flow with PKCE support
- Client Credentials flow
- Resource Server token validation (JWT and opaque tokens)
- OIDC Discovery support
- Comprehensive JWT validation
- PSR-compliant caching with HMAC-based security

## Architecture

The library uses a **Factory → Facade → Specialized Services** pattern:

1. **OidcFactory** - Central factory that creates configured OIDC clients
2. **Oidc** - Main facade providing access to three core flows:
   - `authorizationCode()` - Authorization Code flow for web apps
   - `clientCredentials()` - Client Credentials flow for server-to-server
   - `resourceServer()` - Token validation for resource servers

### Key Components

- **Configuration Layer** (`src/Config/`): ClientMetadata, IssuerMetadata, DiscoveryConfig, StaticConfig
- **Discovery Layer** (`src/Discovery/`): HTTP-based discovery with optional caching
- **Client Layer** (`src/Client/`): OAuth2/OIDC client implementations
- **Resource Server Layer** (`src/ResourceServer/`): Token validators (JWT and opaque)

See [CLAUDE.md](../CLAUDE.md) for detailed architecture documentation.

## Development Commands

### Quality Assurance
```bash
composer checks    # Run all checks (code style, static analysis, tests)
composer cs        # Run code style checker (phpcs)
composer csfix     # Auto-fix code style issues (phpcbf)
composer phpstan   # Run static analysis
composer tests     # Run PHPUnit test suite
```

### Running Tests
```bash
vendor/bin/phpunit                              # Run all tests
vendor/bin/phpunit tests/Specific/TestFile.php # Run specific test file
vendor/bin/phpunit --filter testMethodName     # Run specific test method
vendor/bin/phpunit --no-coverage               # Run tests without coverage (faster)
```

### Before Committing
Always run the following before creating a PR:
```bash
composer csfix    # Fix code style
composer checks   # Verify all checks pass
```

## Coding Standards

### PHP Standards
- **Follow PSR-12 Coding Standard** - This is enforced by phpcs
- **Use strict types** - All PHP files must declare `declare(strict_types=1);`
- **Type everything** - Use type hints for parameters and return types
- **PHP 8.4+ features** - Use modern PHP features (readonly properties, constructor property promotion, etc.)

### Code Style
- Use meaningful variable and method names
- Keep methods focused and single-purpose
- Prefer composition over inheritance
- Use dependency injection
- Follow SOLID principles

### Testing
- **Add tests for all new code** - No PR will be accepted without tests
- Test files mirror source structure: `tests/` matches `src/`
- Use the `TestCase` base class which provides JWT testing utilities
- Test both happy paths and error conditions
- Use descriptive test method names: `testMethodName_WhenCondition_ThenExpectation`

### Security Considerations
- **Never commit secrets** - Use environment variables or configuration
- **Validate all external input** - Especially tokens and URLs
- **Use HMAC for cache keys** - Prevents timing attacks (see `CachingAccessTokenValidator`)
- **Follow OIDC security best practices** - Use PKCE, validate nonces, verify signatures
- **Be mindful of token exposure** - Don't log or display sensitive tokens

## Dependencies

- **PHP 8.4+** - Minimum required version
- **Symfony Contracts** - HTTP Client and Cache contracts (v3.6+)
- **web-token/jwt-library** - JWT operations (v4.0+)

When adding dependencies:
1. Check if functionality exists in current dependencies first
2. Prefer Symfony contracts over concrete implementations
3. Ensure compatibility with PHP 8.4+
4. Update composer.json with `composer require`

## Common Tasks

### Adding a New OIDC Flow
1. Create interface in `src/Client/`
2. Implement the flow class
3. Add factory method to `Oidc` facade
4. Add comprehensive tests
5. Update README.md with usage examples
6. Update CLAUDE.md architecture section

### Adding Token Validation
1. Create validator in `src/ResourceServer/`
2. Implement validation logic with proper error handling
3. Add caching decorator if appropriate
4. Add comprehensive tests including security scenarios
5. Document the validator

### Bug Fixes
1. Write a failing test that demonstrates the bug
2. Fix the bug with minimal changes
3. Verify the test now passes
4. Run full test suite to ensure no regressions
5. Document the fix in commit message

## Git Workflow

- **Branch naming**: Use descriptive branch names (e.g., `fix/token-validation`, `feature/new-flow`)
- **Commit messages**: Clear, descriptive messages explaining what and why
- **One feature per PR**: Keep PRs focused and reviewable
- **Squash commits**: Clean up commit history before merging
- **Update documentation**: Keep README.md, CLAUDE.md, and UPGRADE.md current

## Documentation

- **README.md** - User-facing documentation and examples
- **CLAUDE.md** - Architecture and internal documentation for AI assistants
- **CONTRIBUTING.md** - Contribution guidelines
- **UPGRADE.md** - Breaking changes and migration guides
- **DocBlocks** - Add PHPDoc for public APIs

## Resources

- [OpenID Connect Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [PSR-12 Coding Standard](https://www.php-fig.org/psr/psr-12/)
- [Symfony HTTP Client](https://symfony.com/doc/current/http_client.html)
- [Symfony Cache](https://symfony.com/doc/current/cache.html)

## Notes for Copilot

- This is a **library**, not an application - focus on API design and reusability
- **Security is critical** - this handles authentication and authorization
- **Tests are mandatory** - maintain high coverage and test quality
- **Follow existing patterns** - consistency is important across the codebase
- **Minimal dependencies** - keep the library lightweight
- **Documentation matters** - users rely on clear examples and API docs
