# 🚀 Servex Tutorial Examples

Welcome to the complete Servex tutorial! This progressive learning path takes you from "Hello World" to production-ready web applications.

## 📚 Tutorial Structure

Each tutorial builds on the previous ones, teaching new concepts while reinforcing what you've learned. Follow them in order for the best learning experience.

| # | Tutorial | Difficulty | What You'll Learn | Estimated Time |
|---|----------|------------|-------------------|----------------|
| 0 | [**Plain HTTP + Servex**](00-plain-http/) | 🟢 Beginner | Use Servex utilities with plain net/http | 15 min |
| 1 | [**Hello World**](01-hello-world/) | 🟢 Beginner | Basic server creation, endpoints, JSON responses | 10 min |
| 2 | [**Quickstart**](02-quickstart/) | 🟢 Beginner | Server presets, multiple configurations | 15 min |
| 3 | [**Security Headers**](03-security-headers/) | 🟡 Intermediate | Protect against XSS, clickjacking, and more | 20 min |
| 4 | [**Cache Control**](04-cache-control/) | 🟡 Intermediate | ETags, cache headers, performance optimization | 25 min |
| 5 | [**Static Files**](05-static-files/) | 🟡 Intermediate | File serving, compression, optimization | 20 min |
| 6 | [**Rate Limiting**](06-rate-limiting/) | 🟡 Intermediate | Protect against abuse and DoS attacks | 25 min |
| 7 | [**Request Filtering**](07-request-filtering/) | 🟡 Intermediate | Block bots, validate requests, user agents | 30 min |
| 8 | [**Configuration**](08-configuration/) | 🟡 Intermediate | YAML/JSON config, environment variables | 25 min |
| 9 | [**Simple Proxy**](09-simple-proxy/) | 🟠 Advanced | Reverse proxy, load balancing basics | 35 min |
| 10 | [**Advanced Proxy**](10-advanced-proxy/) | 🔴 Advanced | Complex routing, multiple strategies | 45 min |
| 11 | [**Location Filtering**](11-location-filtering/) | 🔴 Advanced | Location-based filtering and rate limiting | 40 min |
| 12 | [**Dynamic Filtering**](12-dynamic-filtering/) | 🔴 Advanced | Runtime security with honeypots and threat intelligence | 45 min |

**Total estimated time: ~5 hours** (can be done in multiple sessions)

## 🎯 Learning Paths

### 🐣 **Beginner Path** (Start here!)
Perfect if you're new to Servex or web servers in Go:
```
00 → 01 → 02 → 03 → 04 → 05
```
**Goal**: Build a secure, fast web server with caching and static files

### 🔄 **Incremental Adoption Path**
Already have a net/http server? See how to add Servex features gradually:
```
00 → 08 → 01 → 03 → 06
```
**Goal**: Enhance existing applications with Servex utilities

### 🔧 **API Developer Path**
Building REST APIs and microservices:
```
01 → 02 → 03 → 06 → 07 → 08
```
**Goal**: Production-ready API with security, rate limiting, and filtering

### 🌐 **Proxy/Gateway Path**
Building reverse proxies and API gateways:
```
01 → 02 → 08 → 09 → 10 → 11
```
**Goal**: Advanced proxy server with location-based controls

### 🛡️ **Security Expert Path**
Advanced security and dynamic protection:
```
01 → 03 → 06 → 07 → 11 → 12
```
**Goal**: Comprehensive security with runtime threat detection

### 🏭 **Production Path**
Everything you need for production deployments:
```
01 → 02 → 03 → 04 → 06 → 08 → 12
```
**Goal**: Complete production-ready setup with dynamic security

## 🚀 Quick Start

### Option 1: Start the Tutorial
```bash
# Begin with the first tutorial (incremental adoption)
cd 00-plain-http/
go run main.go
# Visit http://localhost:8080

# Or start with full Servex server
cd 01-hello-world/
go run main.go
# Visit http://localhost:8080
```

### Option 2: Jump to a Specific Topic
```bash
# Want to learn about security? Jump to tutorial 3
cd 03-security-headers/
go run main.go

# Want to see proxy features? Try tutorial 9
cd 09-simple-proxy/
go run main.go

# Want to see dynamic security? Try tutorial 12
cd 12-dynamic-filtering/
go run main.go
```

### Option 3: Quick Demo
```bash
# See a comprehensive example
cd 02-quickstart/
go run main.go
# Visit http://localhost:8080 for interactive demo
```

## 📖 Tutorial Features

Each tutorial includes:
- ✅ **Complete, runnable code** - Copy, run, and modify
- ✅ **Step-by-step explanations** - Understand every line
- ✅ **Test commands** - Try it immediately with curl
- ✅ **Real-world examples** - Production-ready patterns
- ✅ **Interactive demos** - See features in action
- ✅ **Clear progression** - Each builds on the previous

## 🎨 Tutorial Format

```
tutorial-name/
├── main.go          # Complete working example
├── go.mod           # Ready-to-run module
├── README.md        # Detailed tutorial guide
└── [optional files] # Config files, certificates, etc.
```

## 🔧 Prerequisites

- **Go 1.24+** (Check with `go version`)
- **Basic Go knowledge** (functions, structs, error handling)
- **Command line familiarity** (cd, go run, curl)

No prior web server experience needed! We'll teach you everything.

## 🧪 Testing Your Progress

Each tutorial includes test commands. Here are some general ones:

```bash
# Basic connectivity
curl http://localhost:8080/

# Check headers
curl -I http://localhost:8080/

# Load testing (install hey first)
go install github.com/rakyll/hey@latest
hey -n 100 -c 10 http://localhost:8080/

# Security check
curl -H "User-Agent: BadBot" http://localhost:8080/
```

## 🆘 Need Help?

### Common Issues
- **Port already in use**: Kill process with `lsof -ti:8080 | xargs kill -9`
- **Dependencies error**: Run `go mod tidy` in the tutorial directory
- **Permission denied**: Use a different port like `:8081`

### Getting Support
- 📖 **Documentation**: Each tutorial has comprehensive docs
- 🐛 **Issues**: Open GitHub issues for bugs
- 💬 **Questions**: Use GitHub discussions
- 📚 **Examples**: This tutorial directory has everything!

## 🎁 What You'll Build

By the end of this tutorial series, you'll have:

### Basic Skills
- ✅ HTTP servers with JSON APIs
- ✅ Security headers and protection
- ✅ Caching and performance optimization
- ✅ Static file serving

### Intermediate Skills  
- ✅ Rate limiting and abuse protection
- ✅ Request filtering and validation
- ✅ Configuration management
- ✅ Advanced proxy patterns

### Advanced Skills
- ✅ Reverse proxy and load balancing
- ✅ Location-based filtering and controls
- ✅ Dynamic security with threat intelligence
- ✅ Runtime security management

## 🌟 Real-World Applications

These tutorials prepare you to build:
- **REST APIs** - Fast, secure, scalable APIs
- **Web Applications** - Full-stack web apps with security
- **Microservices** - Production-ready microservice architectures
- **API Gateways** - Advanced proxy and routing systems
- **Static Sites** - Optimized static file serving
- **Proxy Servers** - Reverse proxies with advanced features
- **Security Systems** - Dynamic threat detection and response

## 🎯 After the Tutorial

Once you complete the tutorials:
1. **Build your project** - Use tutorials as templates
2. **Explore advanced features** - Check the main Servex docs
3. **Join the community** - Share your projects and get help
4. **Contribute back** - Improve these tutorials for others

---

## 🚀 Ready to Start?

🎯 **Begin your journey:** → [00-plain-http](00-plain-http/) or [01-hello-world](01-hello-world/)

**Have existing net/http code?** Start with [00-plain-http](00-plain-http/) to see incremental adoption.

**New to web servers?** Start with [01-hello-world](01-hello-world/) for a gentle introduction.

**Have experience?** Jump to any tutorial that interests you - they're all self-contained!

Happy coding with Servex! 🎉 