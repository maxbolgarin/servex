# Servex Tutorial Examples

Progressive learning path from "Hello World" to production-ready servers. Each tutorial builds on the previous ones.

## Tutorials

| # | Tutorial | Level | What You'll Learn | Time |
|---|----------|-------|-------------------|------|
| 0 | [Plain HTTP + Servex](00-plain-http/) | Beginner | Use Servex context with plain net/http | 15 min |
| 1 | [Hello World](01-hello-world/) | Beginner | Basic server, endpoints, JSON responses | 10 min |
| 2 | [Quickstart & Presets](02-quickstart/) | Beginner | Server presets, multiple configurations | 15 min |
| 3 | [Security Headers](03-security-headers/) | Intermediate | XSS protection, CSP, HSTS, clickjacking | 20 min |
| 4 | [Cache Control](04-cache-control/) | Intermediate | ETags, cache headers, performance | 25 min |
| 5 | [Static Files](05-static-files/) | Intermediate | File serving, compression, SPA mode | 20 min |
| 6 | [Rate Limiting](06-rate-limiting/) | Intermediate | DoS protection, burst control | 25 min |
| 7 | [Request Filtering](07-request-filtering/) | Intermediate | Bot blocking, IP/header/query filtering | 30 min |
| 8 | [Configuration](08-configuration/) | Intermediate | YAML config, environment variables | 25 min |
| 9 | [Simple Proxy](09-simple-proxy/) | Advanced | Reverse proxy, load balancing | 35 min |
| 10 | [Advanced Proxy](10-advanced-proxy/) | Advanced | Complex routing, multiple strategies | 45 min |
| 11 | [Location Filtering](11-location-filtering/) | Advanced | Location-based filtering and rate limiting | 40 min |
| 12 | [Dynamic Filtering](12-dynamic-filtering/) | Advanced | Runtime security, honeypots, threat intel | 45 min |
| 13 | [Standalone & Docker](standalone/) | Any | Run servex without Go code, Docker usage | 20 min |

**Total: ~6 hours** (work through at your own pace)

## Learning Paths

### Beginner
New to Servex or web servers in Go:
```
00 → 01 → 02 → 03 → 04 → 05
```

### Incremental Adoption
Already have a net/http server:
```
00 → 08 → 01 → 03 → 06
```

### API Developer
Building REST APIs and microservices:
```
01 → 02 → 03 → 06 → 07 → 08
```

### Proxy / Gateway
Building reverse proxies and API gateways:
```
01 → 02 → 08 → 09 → 10 → 11
```

### Security Expert
Advanced security and dynamic protection:
```
01 → 03 → 06 → 07 → 11 → 12
```

### Production Deployment
Everything for production:
```
01 → 02 → 03 → 04 → 06 → 08 → 12
```

### Standalone / Docker
Use servex without writing Go code:
```
08 → 13 (standalone)
```

## Quick Start

```bash
# Start with the first tutorial
cd 00-plain-http && go run main.go

# Or jump to a specific topic
cd 06-rate-limiting && go run main.go

# Or try standalone mode (no Go code)
cd standalone && servex -preset production -port 8080
```

## Tutorial Format

```
example-name/
├── main.go          # Complete working example
├── go.mod           # Ready-to-run module
├── README.md        # Detailed guide
└── [optional]       # Config files, static assets, etc.
```

## Prerequisites

- **Go 1.24+** (`go version`)
- **Basic Go knowledge** (functions, structs, error handling)
- **curl** for testing endpoints

## Troubleshooting

- **Port in use**: `lsof -ti:8080 | xargs kill -9`
- **Dependencies**: Run `go mod tidy` in the example directory
- **Permission denied**: Use a different port like `:8081`
