# Contributing to Gazorpazorp

Thank you for your interest in contributing to Gazorpazorp! This document provides guidelines and instructions for contributing to this zero-trust security gateway for autonomous AI agents.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Security](#security)
- [Pull Request Process](#pull-request-process)
- [Documentation](#documentation)

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow:

- Be respectful and inclusive
- Focus on constructive feedback
- Prioritize security and reliability
- Document your changes thoroughly

## Getting Started

### Prerequisites

- Node.js 18+ (LTS recommended)
- Redis 6.0+
- Ollama with local LLM models (for semantic analysis)
- Git

### Initial Setup

1. **Fork the repository**
   ```bash
   git clone https://github.com/yourusername/gazorpazorp.git
   cd gazorpazorp
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up Redis**
   ```bash
   # Using Docker
   docker run -d -p 6379:6379 redis:7-alpine

   # Or install locally
   brew install redis  # macOS
   sudo apt install redis  # Ubuntu
   ```

4. **Set up Ollama** (for LLM-based semantic analysis)
   ```bash
   # Install Ollama
   curl -fsSL https://ollama.com/install.sh | sh

   # Pull required models
   ollama pull llama3.2:3b  # Fast model
   ollama pull llama3.2:7b  # Deep model
   ```

5. **Create configuration**
   ```bash
   cp config.example.json config.json
   # Edit config.json with your settings
   ```

6. **Run tests**
   ```bash
   npm run test
   ```

7. **Start development server**
   ```bash
   npm run dev
   ```

## Development Workflow

### Branching Strategy

- `main` - Production-ready code
- `develop` - Integration branch for features
- `feature/*` - New features
- `fix/*` - Bug fixes
- `security/*` - Security improvements

### Creating a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### Making Changes

1. Write code following our [Code Standards](#code-standards)
2. Add tests for new functionality
3. Update documentation
4. Run the full test suite
5. Commit with clear, descriptive messages

### Commit Message Convention

We follow conventional commits:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `security`: Security fixes

**Examples:**
```bash
git commit -m "feat(crypto): add Ed25519 key rotation support"
git commit -m "fix(rate-limit): prevent race condition in Lua script"
git commit -m "security(headers): sanitize all input headers"
git commit -m "docs(readme): add docker-compose examples"
```

## Code Standards

### TypeScript Guidelines

1. **No `any` types** - Use proper types or `unknown`
   ```typescript
   // ❌ Bad
   function process(data: any) { }

   // ✅ Good
   function process(data: RequestData) { }
   ```

2. **Use interfaces for configuration**
   ```typescript
   // Define in src/types/
   export interface ServiceConfig {
     timeout: number;
     retries: number;
   }
   ```

3. **Add JSDoc comments** for public APIs
   ```typescript
   /**
    * Verify agent cryptographic signature
    * @param signature - Base64-encoded signature
    * @param publicKey - Agent's Ed25519 public key
    * @returns Verification result with agent identity
    */
   async verifySignature(signature: string, publicKey: string): Promise<VerificationResult>
   ```

4. **Use async/await** instead of callbacks
   ```typescript
   // ❌ Bad
   redis.get(key, (err, data) => { })

   // ✅ Good
   const data = await redis.get(key);
   ```

### Security Guidelines

**CRITICAL**: All contributions must maintain security standards:

1. **Never use `as any` or `@ts-ignore`**
2. **Always sanitize external input** (headers, body, query params)
3. **Use constant-time comparison** for crypto operations
4. **Add rate limiting** to new endpoints
5. **Log security events** for audit trail
6. **Validate all configuration** values
7. **Use Lua scripts** for atomic Redis operations

### Code Style

We use Prettier and ESLint:

```bash
# Format code
npm run format

# Lint code
npm run lint
```

**Key style points:**
- 2 spaces for indentation
- Double quotes for strings
- Semicolons required
- Max line length: 120 characters
- No trailing whitespace

## Testing

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run specific test file
npm test tests/crypto.test.ts

# Generate coverage report
npm run test:coverage
```

### Writing Tests

1. **Every feature needs tests**
   ```typescript
   describe("ChallengeService", () => {
     it("should verify Ed25519 signature refresh", async () => {
       const result = await challengeService.verifyChallenge({
         challengeId: "ch_123",
         solution: signedNonce
       });

       expect(result.valid).toBe(true);
     });
   });
   ```

2. **Test security boundaries**
   - Invalid inputs
   - Malicious payloads
   - Rate limit enforcement
   - Authentication failures

3. **Mock external dependencies**
   ```typescript
   const mockRedis = {
     get: vi.fn(),
     set: vi.fn()
   };
   ```

### Test Coverage Requirements

- Minimum 80% coverage for new code
- 100% coverage for security-critical modules:
  - `src/crypto/`
  - `src/challenge/`
  - `src/policy/`

## Security

### Reporting Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email security@example.com with details
2. Include steps to reproduce
3. Provide suggested fix if possible
4. Allow 90 days for patch before public disclosure

### Security Review Checklist

Before submitting security-related PRs:

- [ ] No secrets in code or config
- [ ] All inputs validated and sanitized
- [ ] Rate limiting on new endpoints
- [ ] Proper error messages (no information leakage)
- [ ] Audit logging for security events
- [ ] Cryptographic operations use secure libraries
- [ ] No SQL injection, XSS, or injection vulnerabilities
- [ ] Tests cover attack scenarios

## Pull Request Process

### Before Submitting

1. **Update your branch**
   ```bash
   git checkout main
   git pull origin main
   git checkout your-branch
   git rebase main
   ```

2. **Run full test suite**
   ```bash
   npm run typecheck
   npm run test:run
   npm run build
   ```

3. **Update documentation**
   - Update README if behavior changes
   - Add/update JSDoc comments
   - Update CHANGELOG.md

### PR Template

When creating a PR, include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Security improvement
- [ ] Documentation update
- [ ] Performance improvement

## Testing
- [ ] All tests pass
- [ ] Added new tests for changes
- [ ] Manual testing completed

## Security Impact
- [ ] No security impact
- [ ] Security improvement
- [ ] Requires security review

## Documentation
- [ ] Updated README
- [ ] Updated JSDoc
- [ ] Updated CHANGELOG

## Breaking Changes
List any breaking changes
```

### Review Process

1. Automated checks must pass:
   - TypeScript compilation
   - Tests (79/79 passing)
   - Linting

2. Code review by maintainer:
   - Code quality
   - Security considerations
   - Test coverage
   - Documentation

3. Approval and merge

### Getting Help

If you're stuck:
- Open a draft PR with questions
- Ask in discussions
- Tag maintainers for guidance

## Documentation

### What to Document

1. **Public APIs** - Full JSDoc with examples
2. **Security features** - Explain threat model and mitigation
3. **Configuration** - Document all config options
4. **Architecture** - High-level design docs for major changes

### Documentation Style

```typescript
/**
 * Verify signature refresh challenge solution.
 *
 * Uses Ed25519 cryptographic signature verification to ensure the agent
 * signed the challenge nonce with their registered private key.
 *
 * @param solution - Hex-encoded signature of the challenge nonce
 * @param nonce - Original challenge nonce that was signed
 * @param agentId - Unique identifier of the agent
 * @returns true if signature is valid, false otherwise
 *
 * @throws {Error} If agent identity not found
 *
 * @example
 * ```typescript
 * const valid = await verifySignatureRefresh(
 *   "a1b2c3...",
 *   "challenge_nonce_123",
 *   "agent_456"
 * );
 * ```
 */
async verifySignatureRefresh(
  solution: string,
  nonce: string,
  agentId: string
): Promise<boolean>
```

## Project Structure

```
gazorpazorp/
├── src/
│   ├── gateway/          # Main gateway and middleware
│   ├── crypto/           # Cryptographic verification
│   ├── semantic/         # LLM-based intent analysis
│   ├── policy/           # Policy engine
│   ├── challenge/        # Challenge-response system
│   ├── cache/            # Caching layer
│   ├── behavioral/       # Anomaly detection
│   ├── observability/    # Metrics and monitoring
│   ├── types/            # TypeScript type definitions
│   └── utils/            # Utilities (logger, circuit breaker)
├── tests/                # Test files
├── docs/                 # Additional documentation
└── examples/             # Example clients and usage
```

## Performance Considerations

When contributing:
- Use Redis pipelines for multiple operations
- Implement caching where appropriate
- Use Lua scripts for atomic operations
- Avoid N+1 queries
- Profile performance-critical paths

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License.

## Questions?

- Open an issue for bugs
- Use discussions for questions
- Tag @maintainers for urgent issues

---

Thank you for contributing to Gazorpazorp! 🛡️
