# Tutorial 12: Dynamic Filtering

Master runtime security with **dynamic filter management** that adapts to threats in real-time. This advanced tutorial demonstrates honeypot traps, automatic IP blocking, threat intelligence integration, and security monitoring systems that protect your application from evolving threats.

## 🎯 What You'll Learn

- **Runtime Filter Updates**: Modify security rules without restarting the server
- **Honeypot Security**: Automatic threat detection and IP blocking
- **Threat Intelligence**: Integration with external security feeds
- **Security Monitoring**: Real-time threat detection and alerting
- **Temporary Blocking**: Time-based IP restrictions with auto-expiration
- **Pattern Detection**: Identify and block malicious behavior automatically
- **Emergency Response**: Rapid security lockdown capabilities

## 🛡️ Dynamic Security Architecture

```
🕷️ Honeypot Traps    → Auto-block attacking IPs
🔍 Pattern Detection → Block suspicious behavior
⏰ Temporary Blocks  → Time-based restrictions  
📊 Threat Intel      → External security feeds
🚨 Alert System     → Real-time monitoring
🔧 Manual Control   → Admin security management
```

## 🚀 Quick Start

```bash
# Start the dynamic security server
go run main.go

# Check current security status
curl http://localhost:8080/security-status

# View blocked IPs and security events
curl http://localhost:8080/security-dashboard
```

## 🕷️ Honeypot Security System

### Automatic Threat Detection

The server includes **honeypot endpoints** that automatically block any IP that accesses them:

```bash
# These endpoints trigger automatic IP blocking
curl http://localhost:8080/admin/backup.sql     # Database honeypot
curl http://localhost:8080/wp-admin/           # WordPress honeypot  
curl http://localhost:8080/.env                # Environment file honeypot
curl http://localhost:8080/config/database.yml # Config file honeypot
```

**After accessing any honeypot, your IP will be automatically blocked!**

### Testing Honeypot System

```bash
# 1. Check your current IP status
curl http://localhost:8080/security-status

# 2. Trigger honeypot (this will block you!)
curl http://localhost:8080/admin/backup.sql

# 3. Try accessing legitimate endpoint (should be blocked)
curl http://localhost:8080/api/users

# 4. Check security dashboard to see the block
curl http://localhost:8080/security-dashboard
```

## 🔍 Pattern-Based Threat Detection

The system automatically detects and blocks suspicious patterns:

### Vulnerability Scanning Detection
```bash
# These requests trigger pattern-based blocking
curl http://localhost:8080/admin/phpmyadmin    # Admin panel scanning
curl http://localhost:8080/wp-content/        # WordPress scanning
curl http://localhost:8080/api/users?debug=1  # Debug parameter abuse
curl "http://localhost:8080/search?q=<script>" # XSS attempt
```

### Bot Detection
```bash
# Bad user agents are automatically blocked
curl -H "User-Agent: BadBot/1.0" http://localhost:8080/api/users
curl -H "User-Agent: SQLMap/1.0" http://localhost:8080/api/data
curl -H "User-Agent: " http://localhost:8080/api/posts  # Empty user agent
```

## ⏰ Temporary Blocking System

### Time-Based Restrictions

```bash
# Trigger temporary 2-minute block
curl http://localhost:8080/api/rate-test

# Check when block expires
curl http://localhost:8080/security-status

# Blocks automatically expire (wait 2+ minutes and retry)
curl http://localhost:8080/api/rate-test
```

### Escalating Penalties

```bash
# Multiple violations increase block duration
curl http://localhost:8080/trigger-temp-block  # 1 minute
curl http://localhost:8080/trigger-temp-block  # 5 minutes
curl http://localhost:8080/trigger-temp-block  # 15 minutes
```

## 🔧 Manual Security Management

### Block/Unblock IPs Manually

```bash
# Block an IP manually
curl -X POST http://localhost:8080/admin/security/block \
     -d "ip=192.168.1.100" \
     -d "reason=Manual security block"

# Unblock an IP
curl -X POST http://localhost:8080/admin/security/unblock \
     -d "ip=192.168.1.100"

# Block with duration
curl -X POST http://localhost:8080/admin/security/temp-block \
     -d "ip=192.168.1.100" \
     -d "duration=3600"  # 1 hour
```

### User Agent Management

```bash
# Block user agent patterns
curl -X POST http://localhost:8080/admin/security/block-ua \
     -d "pattern=.*[Bb]ot.*" \
     -d "reason=Block all bot patterns"

# Remove user agent block
curl -X POST http://localhost:8080/admin/security/unblock-ua \
     -d "pattern=.*[Bb]ot.*"
```

## 📊 Security Monitoring & Analytics

### Real-Time Security Dashboard

```bash
# Comprehensive security overview
curl http://localhost:8080/security-dashboard
```

Returns detailed security metrics:
```json
{
  "title": "Dynamic Security Dashboard",
  "status": "active",
  "blocked_ips": {
    "total": 15,
    "permanent": 8,
    "temporary": 7,
    "honeypot_triggered": 5,
    "manual_blocks": 3
  },
  "security_events": {
    "total_today": 45,
    "honeypot_hits": 12,
    "pattern_detections": 18,
    "bot_blocks": 15
  },
  "recent_threats": [
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "ip": "203.0.113.50",
      "type": "honeypot",
      "trigger": "/admin/backup.sql",
      "user_agent": "curl/7.68.0"
    }
  ]
}
```

### Security Event Stream

```bash
# Real-time security events (Server-Sent Events)
curl http://localhost:8080/security-events
```

Streams live security events:
```
event: security_block
data: {"ip": "203.0.113.50", "type": "honeypot", "trigger": "/admin/backup.sql"}

event: pattern_detection  
data: {"ip": "198.51.100.25", "pattern": "vulnerability_scan", "path": "/wp-admin/"}

event: temp_block_expired
data: {"ip": "192.168.1.100", "duration": 120, "reason": "Rate limit exceeded"}
```

## 🌍 Threat Intelligence Integration

### External Security Feeds

```bash
# Update threat intelligence from external sources
curl -X POST http://localhost:8080/admin/security/update-threat-intel

# View current threat intelligence status
curl http://localhost:8080/security-threat-intel
```

### Simulated Threat Feeds

The system includes simulated threat intelligence sources:

```bash
# Check if IP is in threat intelligence feeds
curl "http://localhost:8080/security-check-ip?ip=203.0.113.50"

# View threat intelligence statistics
curl http://localhost:8080/admin/security/threat-stats
```

## 💻 Advanced Features Demo

### Emergency Lockdown Mode

```bash
# Activate emergency security lockdown
curl -X POST http://localhost:8080/admin/security/lockdown \
     -d "level=high" \
     -d "reason=Security incident"

# Check lockdown status
curl http://localhost:8080/security-status

# Deactivate lockdown
curl -X POST http://localhost:8080/admin/security/unlock
```

### Security Analytics Export

```bash
# Export security logs for analysis
curl http://localhost:8080/admin/security/export \
     -o security_report.json

# Get security metrics summary
curl http://localhost:8080/admin/security/metrics
```

### Whitelist Management

```bash
# Add trusted IP to whitelist
curl -X POST http://localhost:8080/admin/security/whitelist \
     -d "ip=192.168.1.0/24" \
     -d "reason=Internal network"

# Remove from whitelist
curl -X DELETE http://localhost:8080/admin/security/whitelist \
     -d "ip=192.168.1.0/24"
```

## 🏗️ Production Implementation Patterns

### Configuration-Driven Security

```go
// Example: Load security rules from config
securityConfig := DynamicSecurityConfig{
    HoneypotEndpoints: []string{
        "/admin/backup.sql", "/.env", "/wp-admin/*",
        "/config/*", "/.git/*", "/database.yml",
    },
    AutoBlockPatterns: []string{
        ".*[Ss]qlmap.*", ".*[Nn]map.*", ".*[Bb]urp.*",
        ".*[Cc]rawler.*", ".*[Ss]craper.*",
    },
    TempBlockDuration: 5 * time.Minute,
    MaxBlockDuration:  24 * time.Hour,
    ThreatIntelFeeds: []string{
        "https://feeds.example.com/malicious-ips",
        "https://threat-intel.example.com/api/v1/ips",
    },
}
```

### Database Integration

```go
// Example: Persist security data
type SecurityDatabase interface {
    StoreSecurityEvent(event SecurityEvent) error
    GetBlockedIPs() ([]BlockedIP, error)
    AddIPToBlocklist(ip string, reason string, duration time.Duration) error
    RemoveIPFromBlocklist(ip string) error
    GetSecurityMetrics() (*SecurityMetrics, error)
}
```

### Alerting Integration

```go
// Example: Security alert system
type SecurityAlerter interface {
    SendAlert(event SecurityEvent) error
    SendCriticalAlert(message string) error
    NotifyAdmins(incident SecurityIncident) error
}

// Slack, email, webhook integrations
alerter := NewSlackAlerter(webhookURL)
alerter.SendCriticalAlert("Multiple honeypot hits detected from 203.0.113.0/24")
```

## 🎯 Testing Scenarios

### Complete Security Test Suite

```bash
#!/bin/bash
echo "🧪 Running Dynamic Security Test Suite"

# Test 1: Honeypot Detection
echo "1. Testing honeypot auto-blocking..."
curl -s http://localhost:8080/admin/backup.sql

# Test 2: Pattern Detection
echo "2. Testing pattern-based detection..."
curl -s -H "User-Agent: SQLMap/1.0" http://localhost:8080/api/users

# Test 3: Temporary Blocking
echo "3. Testing temporary blocks..."
curl -s http://localhost:8080/trigger-temp-block

# Test 4: Manual Management
echo "4. Testing manual IP management..."
curl -s -X POST http://localhost:8080/admin/security/block -d "ip=test.example.com"

# Test 5: Security Monitoring
echo "5. Testing security dashboard..."
curl -s http://localhost:8080/security-dashboard | jq .

echo "✅ Security test suite completed!"
```

## ⚠️ Production Considerations

### Performance Impact
- **Filtering overhead**: ~0.1-0.5ms per request
- **Memory usage**: ~1-5MB for 10,000 blocked IPs
- **Database calls**: Async for non-blocking performance
- **Cache efficiency**: In-memory checks with periodic DB sync

### Scaling Strategies
- **Redis clustering**: Share block lists across instances
- **Database sharding**: Partition security data by region
- **CDN integration**: Push blocks to edge servers
- **Load balancer rules**: Upstream IP blocking

### Security Best Practices
- **Log everything**: Comprehensive audit trails
- **Rate limit admin endpoints**: Prevent abuse of security controls
- **Encrypt sensitive data**: Block reasons, admin actions
- **Regular cleanup**: Remove expired blocks and old events
- **Backup security data**: Don't lose threat intelligence

### Monitoring & Alerting
- **Critical alerts**: Mass honeypot hits, admin abuse
- **Trending analysis**: Unusual IP patterns, new attack vectors
- **Performance monitoring**: Filter response times, memory usage
- **Integration testing**: Regular security system validation

## 📚 What You've Learned

- ✅ **Runtime Security**: Dynamic rule updates without downtime
- ✅ **Automated Defense**: Honeypots and pattern detection
- ✅ **Threat Intelligence**: External feed integration
- ✅ **Security Monitoring**: Real-time dashboards and alerts  
- ✅ **Temporary Restrictions**: Time-based blocking strategies
- ✅ **Manual Controls**: Admin security management tools
- ✅ **Production Patterns**: Scalable security architectures


**Tutorial 12** provides **adaptive security** that evolves with threats and learns from attacks! 🛡️🔥 