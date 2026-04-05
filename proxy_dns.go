package servex

import (
	"context"
	"fmt"
	"net"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

// DynamicUpstreamConfig configures DNS-based dynamic backend discovery for a proxy rule.
type DynamicUpstreamConfig struct {
	// SRVName is the SRV record name to look up (e.g., "_http._tcp.myservice.consul").
	// When set, port and weight are taken from SRV records.
	SRVName string `yaml:"srv_name" json:"srv_name"`

	// AName is the A/AAAA record hostname to resolve (e.g., "myservice.internal").
	// Used when SRVName is not set.
	AName string `yaml:"a_name" json:"a_name"`

	// Port is the port to use with A record resolution. Required when AName is set.
	Port int `yaml:"port" json:"port"`

	// Scheme is the URL scheme for discovered backends. Default: "http".
	Scheme string `yaml:"scheme" json:"scheme"`

	// RefreshInterval is how often to re-resolve DNS. Default: 30s.
	RefreshInterval time.Duration `yaml:"refresh_interval" json:"refresh_interval"`

	// GracePeriod is how long to use stale cached results when DNS resolution fails. Default: 60s.
	GracePeriod time.Duration `yaml:"grace_period" json:"grace_period"`
}

// isActive returns true if dynamic upstream resolution is configured.
func (c DynamicUpstreamConfig) isActive() bool {
	return c.SRVName != "" || c.AName != ""
}

// upstreamResolver periodically resolves DNS records and updates proxy rule backends.
type upstreamResolver struct {
	config DynamicUpstreamConfig
	rule   *ProxyRule
	pm     *proxyManager
	logger Logger

	mu             sync.Mutex
	lastResolved   []resolvedBackend
	lastResolveErr error
	lastResolveAt  time.Time
}

type resolvedBackend struct {
	host   string
	port   int
	weight int
}

func newUpstreamResolver(config DynamicUpstreamConfig, rule *ProxyRule, pm *proxyManager, logger Logger) *upstreamResolver {
	if config.Scheme == "" {
		config.Scheme = "http"
	}
	if config.RefreshInterval == 0 {
		config.RefreshInterval = 30 * time.Second
	}
	if config.GracePeriod == 0 {
		config.GracePeriod = 60 * time.Second
	}
	return &upstreamResolver{
		config: config,
		rule:   rule,
		pm:     pm,
		logger: logger,
	}
}

// start begins the periodic DNS resolution loop. It performs an initial resolution
// synchronously and then continues in the background.
func (r *upstreamResolver) start(ctx context.Context) error {
	// Initial resolution — log but do not fail: static backends (if any) remain usable.
	if err := r.resolve(); err != nil {
		r.logger.Info("dynamic upstream: initial DNS resolution failed", "error", err,
			"rule", r.rule.Name)
	}

	go r.loop(ctx)
	return nil
}

func (r *upstreamResolver) loop(ctx context.Context) {
	ticker := time.NewTicker(r.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.resolve(); err != nil {
				r.logger.Info("dynamic upstream: DNS resolution failed", "error", err,
					"rule", r.rule.Name)
			}
		}
	}
}

func (r *upstreamResolver) resolve() error {
	var resolved []resolvedBackend
	var err error

	if r.config.SRVName != "" {
		resolved, err = r.resolveSRV()
	} else if r.config.AName != "" {
		resolved, err = r.resolveA()
	} else {
		return nil
	}

	if err != nil {
		r.mu.Lock()
		r.lastResolveErr = err
		// Use grace period: if we have cached results and they're still fresh enough, keep using them.
		if len(r.lastResolved) > 0 && time.Since(r.lastResolveAt) < r.config.GracePeriod {
			r.mu.Unlock()
			return fmt.Errorf("using cached results (grace period): %w", err)
		}
		r.mu.Unlock()
		return err
	}

	r.mu.Lock()
	r.lastResolved = resolved
	r.lastResolveErr = nil
	r.lastResolveAt = time.Now()
	r.mu.Unlock()

	r.updateBackends(resolved)
	return nil
}

func (r *upstreamResolver) resolveSRV() ([]resolvedBackend, error) {
	_, addrs, err := net.LookupSRV("", "", r.config.SRVName)
	if err != nil {
		return nil, fmt.Errorf("SRV lookup %s: %w", r.config.SRVName, err)
	}

	resolved := make([]resolvedBackend, 0, len(addrs))
	for _, addr := range addrs {
		resolved = append(resolved, resolvedBackend{
			host:   addr.Target,
			port:   int(addr.Port),
			weight: int(addr.Weight),
		})
	}
	return resolved, nil
}

func (r *upstreamResolver) resolveA() ([]resolvedBackend, error) {
	addrs, err := net.LookupHost(r.config.AName)
	if err != nil {
		return nil, fmt.Errorf("A/AAAA lookup %s: %w", r.config.AName, err)
	}

	resolved := make([]resolvedBackend, 0, len(addrs))
	for _, addr := range addrs {
		resolved = append(resolved, resolvedBackend{
			host:   addr,
			port:   r.config.Port,
			weight: 1,
		})
	}
	return resolved, nil
}

func (r *upstreamResolver) updateBackends(resolved []resolvedBackend) {
	r.pm.mu.Lock()
	defer r.pm.mu.Unlock()

	// Validate scheme — only allow http and https to prevent SSRF via exotic schemes.
	scheme := r.config.Scheme
	if scheme != "http" && scheme != "https" {
		r.logger.Error("dynamic upstream: rejecting invalid scheme", "scheme", scheme, "rule", r.rule.Name)
		return
	}

	// Build set of desired backend URLs.
	desired := make(map[string]resolvedBackend, len(resolved))
	for _, rb := range resolved {
		// Warn about loopback addresses which may indicate misconfiguration.
		if ip := net.ParseIP(rb.host); ip != nil && ip.IsLoopback() {
			r.logger.Info("dynamic upstream: resolved loopback address, may indicate misconfiguration",
				"rule", r.rule.Name, "host", rb.host)
		}
		backendURL := fmt.Sprintf("%s://%s:%d", scheme, rb.host, rb.port)
		desired[backendURL] = rb
	}

	// Build set of current backend URLs.
	current := make(map[string]*Backend, len(r.rule.backends))
	for _, b := range r.rule.backends {
		current[b.URL] = b
	}

	// Add new backends.
	var newBackends []*Backend
	for urlStr, rb := range desired {
		if _, exists := current[urlStr]; exists {
			continue
		}
		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			r.logger.Error("dynamic upstream: invalid URL", "url", urlStr, "error", err)
			continue
		}
		backend := &Backend{
			URL:    urlStr,
			Weight: rb.weight,
			url:    parsedURL,
		}
		backend.healthy.Store(true)

		// Create reverse proxy for this backend.
		backend.proxy = httputil.NewSingleHostReverseProxy(parsedURL)
		backend.proxy.Transport = r.pm.client.Transport

		newBackends = append(newBackends, backend)
		r.logger.Info("dynamic upstream: added backend", "rule", r.rule.Name, "url", urlStr)
	}

	// Remove stale backends.
	kept := make([]*Backend, 0, len(r.rule.backends))
	for _, b := range r.rule.backends {
		if _, exists := desired[b.URL]; exists {
			kept = append(kept, b)
		} else {
			r.logger.Info("dynamic upstream: removed backend", "rule", r.rule.Name, "url", b.URL)
		}
	}

	// Update rule's backend list.
	r.rule.backends = append(kept, newBackends...)
	r.rule.healthyCount.Store(int32(len(r.rule.backends)))
}
