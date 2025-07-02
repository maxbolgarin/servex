# Tutorial 00: Plain HTTP + Servex Context

This tutorial demonstrates how to use **Servex context utilities** with plain `net/http` without creating a full Servex server. This is perfect for **incremental adoption** - you can start using Servex helpers in your existing HTTP applications.

## 🎯 What You'll Learn

- Use `servex.C(w, r)` to get Servex context from standard HTTP handlers
- Easy JSON responses without manual encoding
- Request body parsing and validation
- Custom header management
- Consistent error handling

## 🚀 Why Use Servex Context with Plain HTTP?

**Incremental Adoption**: Add Servex features to existing applications gradually
- **Easy JSON responses** - No manual header setting or encoding
- **Request body parsing** - Simple JSON data binding
- **Better error handling** - Consistent error responses
- **Header management** - Easy custom header setting

## 📋 Available Endpoints

- `GET  /health` - Health check
- `GET  /api/users` - List users
- `POST /api/users` - Create user
- `GET  /api/search?q=...` - Search with query parameters
- `GET  /api/status` - Status with custom headers
- `GET  /api/error?type=...` - Test error handling

## 🏃 Quick Start

```bash
# Start the server
go run main.go

# Test basic endpoints
curl http://localhost:8080/health
curl http://localhost:8080/api/users
```

## 🧪 Testing the Features

### 1. JSON Responses (GET)
```bash
curl http://localhost:8080/api/users
```

**Output:**
```json
{
  "users": [
    {"id": 1, "name": "Alice", "email": "alice@example.com"},
    {"id": 2, "name": "Bob", "email": "bob@example.com"},
    {"id": 3, "name": "Charlie", "email": "charlie@example.com"}
  ],
  "total": 3,
  "note": "Using Servex context with plain net/http"
}
```

### 2. Request Body Parsing (POST)
```bash
curl -X POST http://localhost:8080/api/users \
     -H 'Content-Type: application/json' \
     -d '{"name":"Dave","email":"dave@example.com"}'
```

**Output:**
```json
{
  "message": "User created successfully",
  "user": {
    "id": 4,
    "name": "Dave",
    "email": "dave@example.com",
    "created_at": "2024-01-15T14:30:00Z"
  }
}
```

### 3. Query Parameters
```bash
curl 'http://localhost:8080/api/search?q=servex&page=2'
```

**Output:**
```json
{
  "query": "servex",
  "page": "2",
  "results": [
    "Result 1 for 'servex'",
    "Result 2 for 'servex'"
  ],
  "note": "Query parameters handled with Servex context"
}
```

### 4. Custom Headers
```bash
curl -I http://localhost:8080/api/status
```

**Headers returned:**
```
X-API-Version: 1.0
X-Server-Type: plain-http
X-Powered-By: Servex Context
Content-Type: application/json
```

### 5. Error Handling
```bash
# Test different error types
curl 'http://localhost:8080/api/error?type=404'
curl 'http://localhost:8080/api/error?type=400'
curl 'http://localhost:8080/api/error?type=500'
```

**404 Output:**
```json
{
  "error": "Resource not found example",
  "code": "NOT_FOUND"
}
```
