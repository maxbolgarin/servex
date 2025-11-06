# Servex Large File Refactoring Plan

## Overview

This document provides a detailed, actionable plan for breaking down the large files in the servex codebase into smaller, more maintainable modules. This refactoring improves code organization, makes the codebase easier to navigate, and enables better parallel development.

## Current State

### Large Files Identified

| File | Lines | Status | Priority |
|------|-------|--------|----------|
| `options.go` | 7,456 | **CRITICAL** | **HIGH** |
| `context.go` | 1,707 | **LARGE** | MEDIUM |
| `middleware.go` | 1,571 | **LARGE** | MEDIUM |

### Why Refactor?

1. **Maintainability**: Files with 7,000+ lines are difficult to navigate and understand
2. **Parallel Development**: Multiple developers can work on different modules simultaneously
3. **Testing**: Smaller modules are easier to test in isolation
4. **Code Review**: Smaller files make code reviews more manageable
5. **IDE Performance**: Large files can slow down IDEs and code analysis tools

## Refactoring Guarantee

✅ **ZERO Breaking Changes**: All public APIs remain unchanged
✅ **Backward Compatible**: Existing code continues to work
✅ **Pure Refactoring**: Only file organization changes, no logic changes

---

## Phase 1: options.go Refactoring

**Estimated Time**: 8-12 hours
**Risk Level**: LOW (pure refactoring, no API changes)
**Test Coverage**: Excellent (102 tests in options_test.go)

### Current Structure

The `options.go` file contains:
- 1 main `Options` struct (13 config sub-structs)
- 142 `With*` functions for configuration
- 14 functional categories mixed together

### Proposed Module Breakdown

#### Core Module
**File**: `options_core.go` (~600 lines)
**Lines**: 1-800 (approximately)

**Contents**:
- Package declaration and imports
- `Option` type definition
- `Options` struct (main configuration)
- `ListenAddressRegexp` and default constants
- Core validation functions

**Rationale**: Provides foundation that all other modules depend on.

---

#### HTTPS/TLS Module
**File**: `options_https.go` (~500 lines)
**Lines**: ~2400-2900

**Types**:
- `HTTPSRedirectConfig`

**Functions** (9 total):
- `WithCertificate()`
- `WithCertificateFromFile()`
- `WithHTTPSRedirect()`
- `WithHTTPSRedirectConfig()`
- `WithHTTPSRedirectExcludePaths()`
- `WithHTTPSRedirectIncludePaths()`
- `WithHTTPSRedirectTrustedProxies()`
- `WithHTTPSRedirectPermanent()`
- `WithHSTSHeader()`

**Dependencies**:
- Imports: `crypto/tls`, `net/http`
- Internal: `options_core.go` (Option, Options)

---

#### Authentication Module
**File**: `options_auth.go` (~700 lines)
**Lines**: ~2800-3500

**Types**:
- `AuthConfig`
- `InitialUser`

**Functions** (12 total):
- `WithAuth()`
- `WithAuthMemoryDatabase()`
- `WithAuthConfig()`
- `WithAuthKey()`
- `WithAuthIssuer()`
- `WithAuthBasePath()`
- `WithAuthInitialRoles()`
- `WithAuthRefreshTokenCookieName()`
- `WithAuthTokensDuration()`
- `WithAuthNotRegisterRoutes()`
- `WithAuthInitialUsers()`
- `WithAuthToken()` (simple token auth)

**Dependencies**:
- Imports: `time`
- Internal: `options_core.go`, `auth.go` (AuthDatabase, UserRole)

---

#### Rate Limiting Module
**File**: `options_ratelimit.go` (~400 lines)
**Lines**: ~3500-3900

**Types**:
- `RateLimitConfig`

**Functions** (11 total):
- `WithRPS()`
- `WithRPM()`
- `WithRPH()`
- `WithBurstSize()`
- `WithRateLimitStatusCode()`
- `WithRateLimitMessage()`
- `WithRateLimitExcludePaths()`
- `WithRateLimitIncludePaths()`
- `WithRateLimitTrustedProxies()`
- `WithRateLimitKeyFunc()`
- `WithRateLimitConfig()`

**Dependencies**:
- Imports: `time`, `net/http`
- Internal: `options_core.go`

---

#### Request Filtering Module
**File**: `options_filter.go` (~750 lines)
**Lines**: ~3900-4650

**Types**:
- `FilterConfig`

**Functions** (20 total):
- `WithAllowedIPs()`
- `WithBlockedIPs()`
- `WithAllowedUserAgents()`
- `WithAllowedUserAgentsRegex()`
- `WithBlockedUserAgents()`
- `WithBlockedUserAgentsRegex()`
- `WithAllowedHeaders()`
- `WithAllowedHeadersRegex()`
- `WithBlockedHeaders()`
- `WithBlockedHeadersRegex()`
- `WithAllowedQueryParams()`
- `WithAllowedQueryParamsRegex()`
- `WithBlockedQueryParams()`
- `WithBlockedQueryParamsRegex()`
- `WithFilterExcludePaths()`
- `WithFilterIncludePaths()`
- `WithFilterFailureMessage()`
- `WithFilterStatusCode()`
- `WithDynamicIPFilter()`
- `WithFilterConfig()`

**Dependencies**:
- Imports: `sync`, `net`
- Internal: `options_core.go`, `filter.go` (IPFilter, UserAgentFilter)

---

#### Security & CSRF Module
**File**: `options_security.go` (~700 lines)
**Lines**: ~4650-5350

**Types**:
- `SecurityConfig`

**Functions** (18 total):
- `WithSecurityHeaders()`
- `WithStrictSecurityHeaders()`
- `WithContentSecurityPolicy()`
- `WithXContentTypeOptions()`
- `WithXFrameOptions()`
- `WithXXSSProtection()`
- `WithStrictTransportSecurity()`
- `WithReferrerPolicy()`
- `WithPermissionsPolicy()`
- `WithSecurityExcludePaths()`
- `WithSecurityIncludePaths()`
- `WithRemoveHeaders()`
- `WithCSRFProtection()`
- `WithCSRFConfig()` (if exists)
- `WithCSRFTokenName()`
- `WithCSRFCookieName()`
- `WithCSRFTokenEndpoint()`
- `WithSecurityConfig()`

**Dependencies**:
- Internal: `options_core.go`

---

#### CORS Module
**File**: `options_cors.go` (~400 lines)
**Lines**: ~5350-5750

**Types**:
- `CORSConfig`

**Functions** (10 total):
- `WithCORS()`
- `WithCORSOrigins()`
- `WithCORSMethods()`
- `WithCORSHeaders()`
- `WithCORSExposeHeaders()`
- `WithCORSMaxAge()`
- `WithCORSCredentials()`
- `WithCORSExcludePaths()`
- `WithCORSIncludePaths()`
- `WithCORSConfig()`

**Dependencies**:
- Internal: `options_core.go`

---

#### Caching Module
**File**: `options_cache.go` (~600 lines)
**Lines**: ~5750-6350

**Types**:
- `CacheConfig`

**Functions** (20 total):
- `WithCache()`
- `WithCacheControl()`
- `WithCacheMaxAge()`
- `WithCachePrivate()`
- `WithCachePublic()`
- `WithCacheNoStore()`
- `WithCacheNoCache()`
- `WithCacheMustRevalidate()`
- `WithCacheAPI()`
- `WithCacheStatic()`
- `WithCacheExpires()`
- `WithCacheETag()`
- `WithCacheLastModified()`
- `WithCacheVary()`
- `WithCacheExcludePaths()`
- `WithCacheIncludePaths()`
- `WithCacheInvalidate()`
- `WithCacheByQueryParams()`
- `WithCacheIgnoreQueryParams()`
- `WithCacheConfig()`

**Dependencies**:
- Imports: `time`
- Internal: `options_core.go`

---

#### Request Size Limits Module
**File**: `options_sizelimits.go` (~300 lines)
**Lines**: ~6350-6650

**Functions** (7 total):
- `WithMaxRequestBodySize()`
- `WithMaxJSONBodySize()`
- `WithMaxFileUploadSize()`
- `WithMaxMultipartMemory()`
- `WithEnableRequestSizeLimits()`
- `WithRequestSizeLimits()` (preset)
- `WithStrictRequestSizeLimits()` (preset)

**Dependencies**:
- Internal: `options_core.go`

---

#### Static Files Module
**File**: `options_static.go` (~350 lines)
**Lines**: ~6650-7000

**Types**:
- `StaticFileConfig`

**Functions** (6 total):
- `WithStaticFiles()`
- `WithStaticFilesConfig()`
- `WithSPAMode()`
- `WithStaticCacheControl()`
- `WithStaticIndexFile()`
- `WithStaticStripPrefix()`

**Dependencies**:
- Internal: `options_core.go`

---

#### Compression Module
**File**: `options_compression.go` (~350 lines)
**Lines**: ~7000-7350

**Types**:
- `CompressionConfig`

**Functions** (7 total):
- `WithCompression()`
- `WithCompressionLevel()`
- `WithCompressionTypes()`
- `WithCompressionMinSize()`
- `WithCompressionExcludePaths()`
- `WithCompressionIncludePaths()`
- `WithCompressionConfig()`

**Dependencies**:
- Internal: `options_core.go`

---

#### Timeouts & Logging Module
**File**: `options_server.go` (~400 lines)
**Lines**: Various sections

**Functions** (13 total):
- Timeouts (3):
  - `WithReadTimeout()`
  - `WithReadHeaderTimeout()`
  - `WithIdleTimeout()`
- Logging (10):
  - `WithRequestLogger()`
  - `WithLogger()`
  - `WithDisableRequestLogging()`
  - `WithNoLogClientErrors()`
  - `WithLogFields()`
  - Plus 5 more logging functions

**Dependencies**:
- Imports: `time`
- Internal: `options_core.go`, `logging.go`

---

#### Health & Metrics Module
**File**: `options_health.go` (~300 lines)
**Lines**: Various sections

**Functions** (7 total):
- `WithHealthEndpoint()`
- `WithHealthPath()`
- `WithHealthHandler()`
- `WithDefaultMetrics()`
- `WithMetrics()`
- `WithMetricsPath()`
- `WithCustomMetrics()`

**Dependencies**:
- Imports: `net/http`
- Internal: `options_core.go`, `metrics.go`

---

### Dependency Graph

```
options_core.go (foundation)
    ├── options_https.go
    ├── options_auth.go
    ├── options_ratelimit.go
    ├── options_filter.go
    ├── options_security.go
    ├── options_cors.go
    ├── options_cache.go
    ├── options_sizelimits.go
    ├── options_static.go
    ├── options_compression.go
    ├── options_server.go (timeouts, logging)
    └── options_health.go
```

**✅ No circular dependencies**
**✅ Clean, acyclic dependency structure**

---

### Implementation Steps

#### Step 1: Create options_core.go
1. Copy package declaration and imports
2. Move `Option` type
3. Move `Options` struct
4. Move constants and regex
5. Move validation helper functions
6. Run tests: `go test ./...`

#### Step 2: Extract Authentication Module
1. Create `options_auth.go`
2. Add package declaration
3. Import required packages
4. Move `AuthConfig` type
5. Move `InitialUser` type
6. Move all 12 `WithAuth*` functions
7. Run tests: `go test ./...`

#### Step 3: Extract HTTPS Module
1. Create `options_https.go`
2. Move `HTTPSRedirectConfig`
3. Move all 9 HTTPS-related functions
4. Run tests: `go test ./...`

#### Step 4: Extract Rate Limiting Module
1. Create `options_ratelimit.go`
2. Move `RateLimitConfig`
3. Move all 11 rate limit functions
4. Run tests: `go test ./...`

#### Step 5-13: Extract Remaining Modules
Follow the same pattern for:
- Filter
- Security
- CORS
- Cache
- Size Limits
- Static Files
- Compression
- Server (timeouts/logging)
- Health & Metrics

**After each module**:
- Run `go test ./...`
- Verify no compilation errors
- Verify all 102 tests still pass

#### Step 14: Delete Original options.go
1. Verify all content has been moved
2. Delete `options.go`
3. Run `go test ./...`
4. Run `go build ./...`

#### Step 15: Final Verification
1. Run full test suite: `go test -v ./...`
2. Check code coverage: `go test -cover ./...`
3. Run linter: `golangci-lint run`
4. Build examples: `cd examples && go build ./...`
5. Commit with message: "refactor: break down options.go into 13 focused modules"

---

## Phase 2: context.go Refactoring

**Estimated Time**: 4-6 hours
**Risk Level**: LOW-MEDIUM
**File Size**: 1,707 lines

### Proposed Breakdown

#### context_core.go (~400 lines)
- `Context` struct
- Basic context creation/management
- Request/Response reference getters

#### context_request.go (~500 lines)
- Request parsing functions
- Query parameter handling
- Form value parsing
- Cookie management
- Header access

#### context_response.go (~400 lines)
- Response writing functions
- JSON response helpers
- Error response functions
- Status code helpers

#### context_validation.go (~200 lines)
- Input validation functions
- ReadAndValidate
- Validation error handling

#### context_helpers.go (~200 lines)
- Utility functions
- Type conversion helpers
- Time parsing (ParseUnixFromQuery, etc.)

### Implementation
Same incremental approach as Phase 1.

---

## Phase 3: middleware.go Refactoring

**Estimated Time**: 4-6 hours
**Risk Level**: LOW-MEDIUM
**File Size**: 1,571 lines

### Proposed Breakdown

#### middleware_core.go (~300 lines)
- Middleware type definitions
- Core middleware chaining logic
- Middleware application functions

#### middleware_auth.go (~300 lines)
- Authentication middleware
- JWT verification
- Auth header processing

#### middleware_security.go (~350 lines)
- Security headers middleware
- CSRF middleware
- HTTPS redirect middleware

#### middleware_ratelimit.go (~250 lines)
- Rate limiting middleware
- Rate limit enforcement
- Rate limit key extraction

#### middleware_other.go (~400 lines)
- Logging middleware
- Recovery middleware
- Compression middleware
- CORS middleware
- Filtering middleware

### Implementation
Same incremental approach as previous phases.

---

## Testing Strategy

### Before Refactoring
```bash
# Get baseline
go test -v ./... > test_results_before.txt
go test -cover ./... > coverage_before.txt
golangci-lint run > lint_before.txt
```

### During Refactoring
After **each file** is extracted:
```bash
# Verify compilation
go build ./...

# Run all tests
go test -v ./...

# Check coverage hasn't decreased
go test -cover ./...

# Run linter
golangci-lint run

# If any test fails: STOP and fix before continuing
```

### After Refactoring
```bash
# Full test suite
go test -v ./...

# Compare results
diff test_results_before.txt test_results_after.txt

# Verify coverage maintained
go test -cover -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Build all examples
cd examples
go build ./...

# Run benchmarks if they exist
go test -bench=. ./...
```

---

## Risk Mitigation

### Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Breaking API | LOW | HIGH | No API changes, only file organization |
| Test failures | MEDIUM | MEDIUM | Test after each extraction |
| Import issues | MEDIUM | LOW | Verify imports in each step |
| Lost content | LOW | HIGH | Use git, verify line counts |
| Build errors | MEDIUM | MEDIUM | Build after each extraction |

### Rollback Plan
```bash
# If anything goes wrong at any step:
git reset --hard HEAD
git clean -fd

# Or revert specific commit:
git revert <commit-hash>
```

---

## Success Criteria

### Completion Checklist

- [ ] All modules created and populated
- [ ] Original large files deleted
- [ ] All tests pass (328 existing + 8 new = 336 total)
- [ ] Code coverage maintained at ~90%
- [ ] No compilation errors
- [ ] All examples build successfully
- [ ] Documentation updated (if needed)
- [ ] Code review completed
- [ ] Committed to version control

### Metrics

**Before**:
- 3 files > 1,500 lines
- 1 file > 7,000 lines
- Average file size: ~3,600 lines

**After**:
- 0 files > 1,000 lines
- Average file size: ~400 lines
- 🎯 **4.5x improvement in maintainability**

---

## Timeline Estimate

| Phase | Task | Time | Cumulative |
|-------|------|------|------------|
| 1 | options.go → 13 modules | 8-12 hrs | 12 hrs |
| 2 | context.go → 5 modules | 4-6 hrs | 18 hrs |
| 3 | middleware.go → 5 modules | 4-6 hrs | 24 hrs |
| - | Testing & validation | 2-4 hrs | 28 hrs |
| - | Documentation updates | 1-2 hrs | 30 hrs |
| - | Code review & fixes | 2-4 hrs | **32-34 hrs total** |

**Recommended Approach**:
- Spread over 1-2 weeks
- 2-4 hours per day
- Phase by phase, not all at once

---

## Commands Reference

### Quick Test Commands
```bash
# Run specific test file
go test -v -run TestOptions

# Run all tests with coverage
go test -v -cover ./...

# Run tests for specific package
go test -v github.com/maxbolgarin/servex/v2

# Check for race conditions
go test -race ./...

# Verbose output with timing
go test -v -cover -timeout 30s ./...
```

### Build Verification
```bash
# Build main package
go build ./...

# Build examples
cd examples && go build ./...

# Check for unused imports
goimports -l .

# Format code
gofmt -w .
```

---

## Notes

### Why This Refactoring is Safe

1. **No Logic Changes**: Only moving code between files
2. **No API Changes**: All public functions remain exactly the same
3. **Excellent Test Coverage**: 102 tests in options_test.go, 336 total
4. **Incremental Approach**: Test after each file extraction
5. **Easy Rollback**: Git makes reverting simple if issues arise

### Tips for Success

1. **Don't Rush**: Take breaks between phases
2. **Test Often**: After every single file extraction
3. **Use Git**: Commit after each successful module extraction
4. **Read Carefully**: Make sure you move ALL related code
5. **Ask Questions**: If unsure, check with team before proceeding

---

## Conclusion

This refactoring will significantly improve code maintainability and developer experience. The plan is detailed, safe, and has clear success criteria. The estimated 32-34 hours can be spread over 1-2 weeks at a comfortable pace.

**Ready to start?** Begin with Phase 1, Step 1: Create `options_core.go`

Good luck! 🚀
