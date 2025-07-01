package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/maxbolgarin/servex/v2"
)

func main() {
	fmt.Println("🚀 Servex Tutorial - Static Files")
	fmt.Println("==================================")

	// Create the static files directory and sample files
	setupStaticFiles()

	// Create server with caching optimized for static files
	server, err := servex.NewServer(
		// Basic security and performance for static files
		servex.WithSecurityHeaders(),
		servex.WithCacheStaticAssets(86400), // Cache for 24 hours
	)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Serve static files from ./static directory
	server.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		// Remove "/static/" prefix and serve file
		filepath := r.URL.Path[8:] // Remove "/static/"
		fullPath := "./static/" + filepath

		// Check if file exists
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}

		// Serve the file
		http.ServeFile(w, r, fullPath)
	})

	// API endpoint to list available files
	server.HandleFunc("/api/files", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)

		files, err := listStaticFiles()
		if err != nil {
			ctx.Response(500, map[string]string{
				"error":   "Failed to list files",
				"details": err.Error(),
			})
			return
		}

		ctx.Response(200, map[string]interface{}{
			"files":    files,
			"base_url": "http://localhost:8080/static/",
			"tutorial": "05-static-files",
		})
	})

	// Demo page showing static files
	server.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := `
<!DOCTYPE html>
<html>
<head>
    <title>Static Files Demo</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="container">
        <h1>🚀 Servex Static Files Tutorial</h1>
        <p>This demo shows static file serving with caching and compression.</p>
        
        <h2>📁 Available Files</h2>
        <ul>
            <li><a href="/static/style.css">CSS File</a> - Stylesheet with caching</li>
            <li><a href="/static/app.js">JavaScript File</a> - Client-side script</li>
            <li><a href="/static/logo.txt">Text File</a> - Simple text file</li>
            <li><a href="/static/data.json">JSON File</a> - Sample data</li>
        </ul>
        
        <h2>🧪 Test Commands</h2>
        <pre>
# Check caching headers
curl -I http://localhost:8080/static/style.css

# Check compression
curl -H "Accept-Encoding: gzip" -I http://localhost:8080/static/app.js

# List all files via API
curl http://localhost:8080/api/files
        </pre>
        
        <h2>📊 Features Demonstrated</h2>
        <ul>
            <li>✅ Static file serving from directory</li>
            <li>✅ Cache headers for performance</li>
            <li>✅ Gzip compression for smaller transfers</li>
            <li>✅ Security headers</li>
            <li>✅ File existence checking</li>
        </ul>
        
        <script src="/static/app.js"></script>
    </div>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, html)
	})

	// Health check
	server.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx := servex.C(w, r)
		ctx.Response(200, map[string]string{
			"status":   "healthy",
			"tutorial": "05-static-files",
		})
	})

	fmt.Println("🌐 Server starting on http://localhost:8080")
	fmt.Println("📁 Serving static files from ./static/")
	fmt.Println("")
	fmt.Println("Try these URLs:")
	fmt.Println("  → http://localhost:8080/ (demo page)")
	fmt.Println("  → http://localhost:8080/static/style.css (CSS file)")
	fmt.Println("  → http://localhost:8080/api/files (list files)")
	fmt.Println("")
	fmt.Println("Test caching with: curl -I http://localhost:8080/static/style.css")
	fmt.Println("Press Ctrl+C to stop")

	server.Start(":8080", "")
}

// setupStaticFiles creates the static directory and sample files
func setupStaticFiles() {
	// Create static directory
	os.MkdirAll("./static", 0755)

	// Create sample CSS file
	cssContent := `
/* Servex Static Files Demo */
body {
    font-family: Arial, sans-serif;
    max-width: 800px;
    margin: 0 auto;
    padding: 20px;
    background-color: #f5f5f5;
}

.container {
    background: white;
    padding: 30px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

h1 {
    color: #2c3e50;
    border-bottom: 3px solid #3498db;
    padding-bottom: 10px;
}

h2 {
    color: #34495e;
    margin-top: 30px;
}

ul {
    line-height: 1.6;
}

pre {
    background: #2c3e50;
    color: #ecf0f1;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
}

a {
    color: #3498db;
    text-decoration: none;
}

a:hover {
    text-decoration: underline;
}
`
	os.WriteFile("./static/style.css", []byte(cssContent), 0644)

	// Create sample JavaScript file
	jsContent := `
// Servex Static Files Demo
console.log('🚀 Servex static file loaded successfully!');

document.addEventListener('DOMContentLoaded', function() {
    console.log('📁 Static files demo ready');
    
    // Add some interactivity
    const title = document.querySelector('h1');
    if (title) {
        title.addEventListener('click', function() {
            this.style.color = this.style.color === 'rgb(231, 76, 60)' ? '#2c3e50' : '#e74c3c';
        });
    }
    
    // Fetch and display file info
    fetch('/api/files')
        .then(response => response.json())
        .then(data => {
            console.log('📊 Available files:', data.files);
        })
        .catch(err => console.error('❌ Error fetching files:', err));
});
`
	os.WriteFile("./static/app.js", []byte(jsContent), 0644)

	// Create sample text file
	txtContent := `
Servex Static Files Tutorial
===========================

This is a sample text file served statically by Servex.

Features demonstrated:
- Static file serving
- Cache headers
- Compression
- Security headers

The file is served with appropriate cache headers for performance!
`
	os.WriteFile("./static/logo.txt", []byte(txtContent), 0644)

	// Create sample JSON file
	jsonContent := `{
  "tutorial": "05-static-files",
  "features": [
    "Static file serving",
    "Cache headers", 
    "Compression",
    "Security headers"
  ],
  "files": [
    "style.css",
    "app.js", 
    "logo.txt",
    "data.json"
  ],
  "cache_duration": "24 hours",
  "compression": "gzip",
  "message": "This JSON file is served statically with caching!"
}`
	os.WriteFile("./static/data.json", []byte(jsonContent), 0644)
}

// listStaticFiles returns a list of files in the static directory
func listStaticFiles() ([]string, error) {
	var files []string

	err := filepath.Walk("./static", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			// Remove "./static/" prefix
			relPath := path[9:] // Remove "./static/"
			files = append(files, relPath)
		}

		return nil
	})

	return files, err
}
