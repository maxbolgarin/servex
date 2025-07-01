# Servex Examples

This directory contains comprehensive, runnable examples demonstrating all features of the Servex web framework. Each example is in its own directory with a complete Go module, detailed documentation, and step-by-step instructions.

## 🚀 Quick Start

Choose any example and run it immediately:

```bash
# Navigate to any example directory
cd quickstart/
go run main.go

# Or cache examples
cd cache/
go run main.go

# Or proxy examples  
cd proxy-simple/
go run main.go
```

Each example includes an interactive web interface for hands-on learning.

## 📁 Available Examples

### Core Examples

| Example | Description | Difficulty | Key Features |
|---------|-------------|------------|--------------|
| **[quickstart/](quickstart/)** | Multi-pattern server setups using presets | Beginner | Presets, multiple server types, basic configuration |
| **[cache/](cache/)** | Cache control headers and strategies | Beginner | ETags, cache headers, conditional requests |
| **[security/](security/)** | Security headers and protection | Beginner | CSP, HSTS, XSS protection, security headers |

### Advanced Examples

| Example | Description | Difficulty | Key Features |
|---------|-------------|------------|--------------|
| **[proxy-simple/](proxy-simple/)** | Reverse proxy with load balancing | Intermediate | Load balancing, health checks, traffic dumping |
| **[proxy-gateway/](proxy-gateway/)** | Advanced proxy gateway configuration | Advanced | Complex routing, multiple strategies |
| **[static/](static/)** | Static file serving with optimizations | Intermediate | File serving, compression, caching |

### Feature-Specific Examples

| Example | Description | Difficulty | Key Features |
|---------|-------------|------------|--------------|
| **[filter/](filter/)** | Request filtering and validation | Intermediate | User-agent blocking, parameter filtering |
| **[ratelimit/](ratelimit/)** | Rate limiting strategies | Intermediate | RPS/RPM limits, burst handling |
| **[location-filter/](location-filter/)** | Geographic request filtering | Advanced | IP-based filtering, geo-blocking |
| **[location-ratelimit/](location-ratelimit/)** | Location-based rate limiting | Advanced | Geographic rate limiting |
| **[dynamic-filter/](dynamic-filter/)** | Dynamic request filtering | Advanced | Runtime filter configuration |

### Configuration Examples

| Example | Description | Difficulty | Key Features |
|---------|-------------|------------|--------------|
| **[config/](config/)** | Configuration management | Intermediate | YAML/JSON config, environment variables |
| **[configuration-guide/](configuration-guide/)** | Complete configuration reference | Advanced | All options, best practices |

## 🎯 Examples by Use Case

### Getting Started
- **New to Servex?** → Start with [quickstart/](quickstart/)
- **Need basic security?** → Try [security/](security/)
- **Want caching?** → Check [cache/](cache/)

### Production Setup
- **API Server** → [quickstart/](quickstart/) + [security/](security/) + [cache/](cache/)
- **Reverse Proxy** → [proxy-simple/](proxy-simple/) + [proxy-gateway/](proxy-gateway/)
- **Static Site** → [static/](static/) + [cache/](cache/) + [security/](security/)

### Advanced Features
- **Load Balancing** → [proxy-simple/](proxy-simple/)
- **Rate Limiting** → [ratelimit/](ratelimit/)
- **Request Filtering** → [filter/](filter/) + [dynamic-filter/](dynamic-filter/)
- **Geographic Control** → [location-filter/](location-filter/) + [location-ratelimit/](location-ratelimit/)

## 🏃‍♂️ Running Examples

### Prerequisites
- Go 1.24 or later
- Internet connection (for dependencies)

### Quick Run
Each example can be run independently:

```bash
# Clone the repository
git clone https://github.com/maxbolgarin/servex
cd servex/examples

# Run any example
cd quickstart/
go run main.go

# Visit http://localhost:8080 in your browser
```

### Testing Examples
Most examples include test commands in their README:

```bash
# Basic testing
curl http://localhost:8080/

# Header inspection
curl -I http://localhost:8080/

# Load testing (install hey first)
go install github.com/rakyll/hey@latest
hey -n 100 -c 10 http://localhost:8080/
```

## 📚 Learning Path

### Beginner Path
1. **[quickstart/](quickstart/)** - Learn basic server setup
2. **[security/](security/)** - Add security headers
3. **[cache/](cache/)** - Implement caching
4. **[static/](static/)** - Serve static files

### Intermediate Path
5. **[config/](config/)** - Configuration management
6. **[ratelimit/](ratelimit/)** - Rate limiting
7. **[filter/](filter/)** - Request filtering
8. **[proxy-simple/](proxy-simple/)** - Basic proxying

### Advanced Path
9. **[proxy-gateway/](proxy-gateway/)** - Advanced proxying
10. **[dynamic-filter/](dynamic-filter/)** - Dynamic filtering
11. **[location-filter/](location-filter/)** - Geographic filtering
12. **[configuration-guide/](configuration-guide/)** - Complete reference

## 🔧 Example Structure

Each example follows a consistent structure:

```
example-name/
├── main.go          # Runnable main function
├── go.mod           # Go module with dependencies
├── README.md        # Detailed documentation
└── [config files]   # Any configuration files
```

### Standard Features
Every example includes:
- ✅ **Runnable main()** function
- ✅ **Interactive web interface** (where applicable)
- ✅ **Comprehensive documentation**
- ✅ **Test commands and examples**
- ✅ **Error handling and logging**
- ✅ **Production-ready patterns**

## 🛠️ Development and Testing

### Modifying Examples
1. Navigate to any example directory
2. Edit `main.go` to try different configurations
3. Run `go run main.go` to test changes
4. Check the README for specific testing instructions

### Creating Custom Examples
Use any existing example as a template:

```bash
# Copy an example
cp -r quickstart/ my-example/

# Update go.mod
cd my-example/
sed -i 's/quickstart/my-example/g' go.mod

# Edit main.go and README.md
```

## 📖 Documentation

### Individual READMEs
Each example has detailed documentation:
- **Purpose and scope**
- **Running instructions**
- **Configuration options**
- **Testing commands**
- **Troubleshooting guide**
- **Next steps**

### Code Comments
All examples include extensive code comments explaining:
- Configuration options
- Feature usage
- Best practices
- Common patterns

## 🚦 Common Issues

### Port Already in Use
```bash
# Kill process using port 8080
lsof -ti:8080 | xargs kill -9

# Or use a different port
go run main.go --port 8081
```

### Dependencies Not Found
```bash
# Clean and download dependencies
go mod tidy
go mod download
```

### Permission Issues
```bash
# Make sure you can bind to ports
# On some systems, ports < 1024 require sudo
```

## 🔗 Integration Examples

### Combining Multiple Features
```go
// Example: Production server with all features
server, err := servex.NewServer(
    // Base configuration
    servex.ProductionPreset()...,
    
    // Add caching
    servex.WithCachePublic(3600),
    
    // Add security
    servex.WithStrictSecurityHeaders(),
    
    // Add rate limiting
    servex.WithRPS(100),
    
    // Add proxy
    servex.WithProxyConfig(proxyConfig),
)
```

### Real-World Scenarios
- **API Gateway**: [proxy-gateway/](proxy-gateway/) + [security/](security/) + [ratelimit/](ratelimit/)
- **Static Site**: [static/](static/) + [cache/](cache/) + [security/](security/)
- **Microservice**: [quickstart/](quickstart/) + [ratelimit/](ratelimit/) + [filter/](filter/)

## 📝 Contributing Examples

### Adding New Examples
1. Create a new directory
2. Follow the standard structure
3. Include comprehensive README
4. Add to this main README
5. Test thoroughly

### Improving Existing Examples
1. Fork the repository
2. Make improvements
3. Test changes
4. Submit pull request

## 🔍 Troubleshooting

### Example Won't Start
1. Check Go version: `go version`
2. Verify dependencies: `go mod tidy`
3. Check port availability: `lsof -i :8080`
4. Review error messages in terminal

### Features Not Working
1. Check configuration in `main.go`
2. Review example-specific README
3. Test with provided curl commands
4. Check browser developer tools for web examples

### Performance Issues
1. Use load testing tools: `hey`, `ab`, `wrk`
2. Check rate limiting configuration
3. Monitor resource usage
4. Review proxy configurations

## 📞 Support

- **Documentation**: Check individual example READMEs
- **Issues**: Open GitHub issues for bugs
- **Questions**: Use GitHub discussions
- **Examples**: Refer to this examples directory

## 🎯 Next Steps

After exploring the examples:

1. **Choose Your Use Case**: Select examples relevant to your needs
2. **Combine Features**: Mix and match configurations
3. **Build Your Application**: Use examples as starting templates
4. **Deploy to Production**: Follow production examples and best practices

Happy coding with Servex! 🚀 