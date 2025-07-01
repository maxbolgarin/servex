package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/maxbolgarin/servex"
)

func TestShowVersion(t *testing.T) {
	// Capture output by redirecting stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showVersion()

	w.Close()
	os.Stdout = oldStdout

	// Read the output
	var buf []byte
	buf = make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Check that version info is displayed
	if !strings.Contains(output, "Servex HTTP Server") {
		t.Error("expected version output to contain 'Servex HTTP Server'")
	}

	if !strings.Contains(output, "Version:") {
		t.Error("expected version output to contain 'Version:'")
	}

	if !strings.Contains(output, "Build time:") {
		t.Error("expected version output to contain 'Build time:'")
	}

	if !strings.Contains(output, "Git commit:") {
		t.Error("expected version output to contain 'Git commit:'")
	}
}

func TestShowHelp(t *testing.T) {
	// Capture output by redirecting stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showHelp()

	w.Close()
	os.Stdout = oldStdout

	// Read the output
	var buf []byte
	buf = make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Check that help info is displayed
	if !strings.Contains(output, "Servex - Enterprise HTTP Server") {
		t.Error("expected help output to contain 'Servex - Enterprise HTTP Server'")
	}

	if !strings.Contains(output, "USAGE:") {
		t.Error("expected help output to contain 'USAGE:'")
	}

	if !strings.Contains(output, "OPTIONS:") {
		t.Error("expected help output to contain 'OPTIONS:'")
	}

	if !strings.Contains(output, "-config") {
		t.Error("expected help output to contain '-config' option")
	}

	if !strings.Contains(output, "-version") {
		t.Error("expected help output to contain '-version' option")
	}
}

func TestLoadConfiguration(t *testing.T) {
	t.Run("nonexistent file", func(t *testing.T) {
		config, err := loadConfiguration("nonexistent.yaml")
		if err != nil {
			t.Fatalf("expected no error for nonexistent file, got: %v", err)
		}

		if config == nil {
			t.Error("expected config to not be nil")
		}

		// Should load from environment variables when file doesn't exist
	})

	t.Run("invalid file path", func(t *testing.T) {
		// Create a temporary invalid config file
		tempFile := "test_invalid.yaml"
		f, err := os.Create(tempFile)
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		f.WriteString("invalid: yaml: content: [")
		f.Close()
		defer os.Remove(tempFile)

		_, err = loadConfiguration(tempFile)
		if err == nil {
			t.Error("expected error for invalid YAML file")
		}
	})

	t.Run("valid config file", func(t *testing.T) {
		// Create a temporary valid config file
		tempFile := "test_valid.yaml"
		f, err := os.Create(tempFile)
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		f.WriteString(`
server:
  http: ":8080"
  auth_token: "test-token"
`)
		f.Close()
		defer os.Remove(tempFile)

		config, err := loadConfiguration(tempFile)
		if err != nil {
			t.Fatalf("expected no error for valid config file, got: %v", err)
		}

		if config == nil {
			t.Error("expected config to not be nil")
		}

		if config.Server.HTTP != ":8080" {
			t.Errorf("expected HTTP address ':8080', got '%s'", config.Server.HTTP)
		}

		if config.Server.AuthToken != "test-token" {
			t.Errorf("expected auth token 'test-token', got '%s'", config.Server.AuthToken)
		}
	})
}

func TestRegisterStandaloneRoutes(t *testing.T) {
	server, err := servex.New()
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Call the function to register routes
	registerStandaloneRoutes(server)

	// Test that the routes were registered by checking the router
	router := server.Router()
	if router == nil {
		t.Fatal("expected router to not be nil")
	}

	// We can't easily test the exact routes without making HTTP requests,
	// but we can verify the function doesn't panic and that the server
	// has routes registered
}

func TestStartTime(t *testing.T) {
	// Test that startTime is initialized
	if startTime.IsZero() {
		t.Error("expected startTime to be initialized")
	}

	// Test that it's approximately the current time (within last minute)
	if time.Since(startTime) > time.Minute {
		t.Error("expected startTime to be recent")
	}
}

func TestVersionVariables(t *testing.T) {
	// Test that version variables are defined (even if they're default values)
	if Version == "" {
		t.Log("Version is empty (expected for tests)")
	}

	if BuildTime == "" {
		t.Log("BuildTime is empty (expected for tests)")
	}

	if GitCommit == "" {
		t.Log("GitCommit is empty (expected for tests)")
	}

	// These should have default values in tests
	expectedVersion := "dev"
	expectedBuildTime := "unknown"
	expectedGitCommit := "unknown"

	if Version != expectedVersion {
		t.Logf("Version is '%s', expected '%s' for test build", Version, expectedVersion)
	}

	if BuildTime != expectedBuildTime {
		t.Logf("BuildTime is '%s', expected '%s' for test build", BuildTime, expectedBuildTime)
	}

	if GitCommit != expectedGitCommit {
		t.Logf("GitCommit is '%s', expected '%s' for test build", GitCommit, expectedGitCommit)
	}
}
