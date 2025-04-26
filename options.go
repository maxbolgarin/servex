package servex

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

var (
	// ListenAddressRegexp is used to match "ip:port" or ":port" strings or kuber domains with port.
	ListenAddressRegexp = regexp.MustCompile(`^[\w\-\/:@\.]*:[0-9]{1,5}$`)

	defaultReadTimeout = 60 * time.Second
	defaultIdleTimeout = 180 * time.Second
)

// Metrics is an interface for collecting metrics on each request.
// [Metrics.HandleRequest] is called on each request.
type Metrics interface {
	// HandleRequest is called on each request to collect metrics.
	HandleRequest(r *http.Request)
}

type Option func(*Options)

// Options represents the configuration for a server.
type Options struct {
	// Certificate is the TLS certificate for the server.
	// If not set, the server will not start HTTPS server.
	Certificate *tls.Certificate

	// ReadTimeout is the maximum duration for reading the entire request.
	ReadTimeout time.Duration

	// ReadHeaderTimeout is the maximum duration for reading the request headers.
	ReadHeaderTimeout time.Duration

	// IdleTimeout is the maximum duration the server should keep connections alive.
	IdleTimeout time.Duration

	// AuthToken is the token that will be checked in the Authorization header.
	AuthToken string

	// Metrics is the metrics handler for the server.
	Metrics Metrics

	// Logger is the logger for the server.
	// If not set, there will be [slog.New] with [slog.NewJSONHandler] with logging to stderr.
	// Debug level is used to log successful requests if RequestLogger is not set.
	// Info level is used to log 'http(s) server started'
	// Error level is used to log request errors, panics, serve errors and shutodwn in StartContext errors
	Logger Logger

	// RequestLogger is the logger for the requests.
	// If not set it will use [Options.Logger].
	RequestLogger RequestLogger

	// NoLogClientErrors, if true, will not log client errors with code 400-499
	NoLogClientErrors bool

	// Auth is the auth configuration for the server.
	Auth AuthConfig
}

// AuthConfig holds the configuration specific to authentication.
type AuthConfig struct {
	// Database is the interface for user data persistence.
	Database AuthDatabase

	// JWTAccessSecret is the secret key used for signing access tokens (hex encoded).
	// If empty, a random key will be generated.
	JWTAccessSecret string

	// JWTRefreshSecret is the secret key used for signing refresh tokens (hex encoded).
	// If empty, a random key will be generated.
	JWTRefreshSecret string

	// AccessTokenDuration specifies the validity duration for access tokens.
	// Defaults to 5 minutes if not set.
	AccessTokenDuration time.Duration

	// RefreshTokenDuration specifies the validity duration for refresh tokens.
	// Defaults to 7 days if not set.
	RefreshTokenDuration time.Duration

	// IssuerNameInJWT is the issuer name included in the JWT claims.
	// Defaults to "testing" if not set.
	IssuerNameInJWT string

	// RefreshTokenCookieName is the name of the cookie used to store the refresh token.
	// Defaults to "_servexrt" if not set.
	RefreshTokenCookieName string

	// AuthBasePath is the base path for the authentication API endpoints.
	// Defaults to "/api/v1/auth" if not set.
	AuthBasePath string

	// InitialRoles are the roles assigned to a newly registered user.
	InitialRoles []UserRole

	// NotRegisterRoutes, if true, prevents the automatic registration of default auth routes.
	NotRegisterRoutes bool

	// accessSecret is the decoded access secret key.
	accessSecret []byte

	// refreshSecret is the decoded refresh secret key.
	refreshSecret []byte

	// enabled indicates whether authentication is enabled.
	enabled bool
}

// WithCertificate sets the TLS [Options.Certificate] to the [Options].
// TLS certificate is required to start HTTPS server.
func WithCertificate(cert tls.Certificate) Option {
	return func(op *Options) {
		op.Certificate = &cert
	}
}

// WithReadTimeout sets the [Options.ReadTimeout] of the [Options] to the given duration.
// ReadTimeout is the maximum duration for reading the entire request, including the body.
// A zero or negative value sets default value of 60 seconds.
func WithReadTimeout(tm time.Duration) Option {
	return func(op *Options) {
		if op.ReadTimeout <= 0 {
			op.ReadTimeout = defaultReadTimeout
		}
		op.ReadTimeout = tm
	}
}

// WithReadHeaderTimeout sets the [Options.ReadHeaderTimeout] of the [Options] to the given duration.
// ReadHeaderTimeout is the maximum duration for reading the request headers (without body).
// A zero or negative value means there will be no timeout (using ReadTimeout for all request).
func WithReadHeaderTimeout(tm time.Duration) Option {
	return func(op *Options) {
		if op.ReadHeaderTimeout <= 0 {
			op.ReadHeaderTimeout = 0
		}
		op.ReadHeaderTimeout = tm
	}
}

// WithIdleTimeout sets the [Options.IdleTimeout] of the [Options] to the given duration.
// IdleTimeout is the maximum duration an idle Keep-Alive connection will be kept open.
// A zero or negative value sets default value of 180 seconds.
func WithIdleTimeout(tm time.Duration) Option {
	return func(op *Options) {
		if op.IdleTimeout <= 0 {
			op.IdleTimeout = defaultIdleTimeout
		}
		op.IdleTimeout = tm
	}
}

// WithAuthToken sets the [Options.AuthToken] of the [Options] to the given string.
// AuthToken is the token that will be checked in the Authorization header.
func WithAuthToken(t string) Option {
	return func(op *Options) {
		op.AuthToken = t
	}
}

// WithMetrics sets the [Metrics] to the [Options].
func WithMetrics(m Metrics) Option {
	return func(op *Options) {
		op.Metrics = m
	}
}

// WithLogger sets the [Logger] to the [Options].
// If not set, there will be [slog.New] with [slog.NewJSONHandler]  with logging to stderr.
func WithLogger(l Logger) Option {
	return func(op *Options) {
		op.Logger = l
	}
}

// WithRequestLogger sets the RequestLogger to the [Options].
// If not set it will use [Options.Logger] or [Options.SLogger] in debug level.
func WithRequestLogger(r RequestLogger) Option {
	return func(op *Options) {
		op.RequestLogger = r
	}
}

// WithNoRequestLog disables request logging.
func WithNoRequestLog() Option {
	return func(op *Options) {
		op.RequestLogger = &noopRequestLogger{}
	}
}

// WithNoLogClientErrors disables logging of client errors with code 400-499.
func WithNoLogClientErrors() Option {
	return func(op *Options) {
		op.NoLogClientErrors = true
	}
}

// ReadCertificate is a function that reads a TLS certificate from the given cert and key bytes
// and returns a [tls.Certificate] instance.
func ReadCertificate(cert, key []byte) (tls.Certificate, error) {
	return tls.X509KeyPair(cert, key)
}

// ReadCertificateFromFile is a function that reads a TLS certificate from the given cert and key files
// and returns a [tls.Certificate] instance.
func ReadCertificateFromFile(certFile, keyFile string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}

// WithAuth sets the [Options.Auth.Database] of the [Options] to the given [AuthDatabase] and enables auth.
func WithAuth(db AuthDatabase) Option {
	return func(op *Options) {
		op.Auth.Database = db
		op.Auth.enabled = true
	}
}

// WithAuthMemoryDatabase sets the [Options.Auth.Database] of the [Options] to the in-memory [AuthDatabase] and enables auth.
// NOT RECOMMENDED FOR PRODUCTION USE. It will forget all users on applications shutdown.
func WithAuthMemoryDatabase() Option {
	return func(op *Options) {
		op.Auth.Database = newMemoryAuthDatabase()
		op.Auth.enabled = true
	}
}

// WithAuthConfig sets the [Options.Auth] of the [Options] to the given [AuthConfig].
// It panics if the provided AuthConfig.Database is nil.
func WithAuthConfig(auth AuthConfig) Option {
	if auth.Database == nil {
		panic("auth database is required")
	}
	return func(op *Options) {
		op.Auth = auth
		op.Auth.enabled = true
	}
}

// WithAuthKey sets the [Options.Auth.JWTAccessSecret] and [Options.Auth.JWTRefreshSecret] of the [Options] to the given keys.
func WithAuthKey(accessKey, refreshKey string) Option {
	return func(op *Options) {
		op.Auth.JWTAccessSecret = accessKey
		op.Auth.JWTRefreshSecret = refreshKey
	}
}

// WithAuthIssuer sets the [Options.Auth.IssuerNameInJWT] of the [Options] to the given issuer name.
func WithAuthIssuer(issuer string) Option {
	return func(op *Options) {
		op.Auth.IssuerNameInJWT = issuer
	}
}

// WithAuthBasePath sets the [Options.Auth.AuthBasePath] of the [Options] to the given base path.
func WithAuthBasePath(path string) Option {
	return func(op *Options) {
		op.Auth.AuthBasePath = path
	}
}

// WithAuthInitialRoles sets the [Options.Auth.InitialRoles] of the [Options] to the given roles.
func WithAuthInitialRoles(roles ...UserRole) Option {
	return func(op *Options) {
		op.Auth.InitialRoles = roles
	}
}

// WithAuthRefreshTokenCookieName sets the [Options.Auth.RefreshTokenCookieName] of the [Options] to the given name.
func WithAuthRefreshTokenCookieName(name string) Option {
	return func(op *Options) {
		op.Auth.RefreshTokenCookieName = name
	}
}

// WithAuthTokensDuration sets the [Options.Auth.AccessTokenDuration] and [Options.Auth.RefreshTokenDuration] of the [Options] to the given duration.
func WithAuthTokensDuration(accessDuration, refreshDuration time.Duration) Option {
	return func(op *Options) {
		op.Auth.AccessTokenDuration = accessDuration
		op.Auth.RefreshTokenDuration = refreshDuration
	}
}

// WithAuthNotRegisterRoutes sets the [Options.Auth.NotRegisterRoutes] of the [Options] to the given value.
func WithAuthNotRegisterRoutes(notRegisterRoutes bool) Option {
	return func(op *Options) {
		op.Auth.NotRegisterRoutes = notRegisterRoutes
	}
}

// BaseConfig represents the base configuration for a server without additional options.
// You can use it as a base for your own configuration.
type BaseConfig struct {
	// HTTP is an address to start HTTP listener on.
	HTTP string `yaml:"http" json:"http" env:"SERVER_HTTP"`

	// HTTPS is an address to start HTTPS listener on.
	HTTPS string `yaml:"https" json:"https" env:"SERVER_HTTPS"`

	// CertFile is a path to the TLS certificate file in case of HTTPS.
	CertFile string `yaml:"cert_file" json:"cert_file" env:"SERVER_CERT_FILE"`

	// KeyFile is a path to the TLS key file in case of HTTPS.
	KeyFile string `yaml:"key_file" json:"key_file" env:"SERVER_KEY_FILE"`

	// AuthToken is a token for authorization in Authorization header.
	AuthToken string `yaml:"auth_token" json:"auth_token" env:"SERVER_AUTH_TOKEN"`
}

// Validate checks if the BaseConfig is valid.
// It ensures that at least one of HTTP or HTTPS address is provided and that addresses match the required format.
func (c *BaseConfig) Validate() error {
	if c.HTTP == "" && c.HTTPS == "" {
		return errors.New("at least one of http or https should be set")
	}

	if c.HTTP != "" {
		if !ListenAddressRegexp.MatchString(c.HTTP) {
			return fmt.Errorf("invalid http address=%q", c.HTTP)
		}
	}

	if c.HTTPS != "" {
		if !ListenAddressRegexp.MatchString(c.HTTPS) {
			return fmt.Errorf("invalid https address=%q", c.HTTPS)
		}
	}

	return nil
}

// GetTLSConfig creates a *tls.Config suitable for an HTTPS server using the provided certificate.
// It returns nil if the certificate is nil.
// The config enables HTTP/2, prefers server cipher suites, sets minimum TLS version to 1.2,
// and includes a list of secure cipher suites and curve preferences.
func GetTLSConfig(cert *tls.Certificate) *tls.Config {
	if cert == nil {
		return nil
	}
	return &tls.Config{
		Certificates:             []tls.Certificate{*cert},
		NextProtos:               []string{"h2", "http/1.1"}, // enable HTTP2
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12, // use only new TLS
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // only secure ciphers
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
		},
	}
}

func parseOptions(opts []Option) Options {
	op := Options{}
	for _, o := range opts {
		o(&op)
	}
	return op
}

const (
	// MIMETypeAAC defines the MIME type for AAC audio.
	MIMETypeAAC = "audio/aac"

	// MIMETypeABW defines the MIME type for AbiWord documents.
	MIMETypeABW = "application/x-abiword"

	// MIMETypeAPNG defines the MIME type for Animated Portable Network Graphics (APNG).
	MIMETypeAPNG = "image/apng"

	// MIMETypeARC defines the MIME type for Archive documents (multiple files embedded).
	MIMETypeARC = "application/x-freearc"

	// MIMETypeAVIF defines the MIME type for AVIF images.
	MIMETypeAVIF = "image/avif"

	// MIMETypeAVI defines the MIME type for AVI (Audio Video Interleave).
	MIMETypeAVI = "video/x-msvideo"

	// MIMETypeAZW defines the MIME type for Amazon Kindle eBook format.
	MIMETypeAZW = "application/vnd.amazon.ebook"

	// MIMETypeBIN defines the MIME type for any kind of binary data.
	MIMETypeBIN = "application/octet-stream"

	// MIMETypeBMP defines the MIME type for Windows OS/2 Bitmap Graphics.
	MIMETypeBMP = "image/bmp"

	// MIMETypeBZ defines the MIME type for BZip archives.
	MIMETypeBZ = "application/x-bzip"

	// MIMETypeBZ2 defines the MIME type for BZip2 archives.
	MIMETypeBZ2 = "application/x-bzip2"

	// MIMETypeCDA defines the MIME type for CD audio.
	MIMETypeCDA = "application/x-cdf"

	// MIMETypeCSH defines the MIME type for C-Shell scripts.
	MIMETypeCSH = "application/x-csh"

	// MIMETypeCSS defines the MIME type for Cascading Style Sheets (CSS).
	MIMETypeCSS = "text/css"

	// MIMETypeCSV defines the MIME type for Comma-separated values (CSV).
	MIMETypeCSV = "text/csv"

	// MIMETypeDOC defines the MIME type for Microsoft Word.
	MIMETypeDOC = "application/msword"

	// MIMETypeDOCX defines the MIME type for Microsoft Word (OpenXML).
	MIMETypeDOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

	// MIMETypeEOT defines the MIME type for MS Embedded OpenType fonts.
	MIMETypeEOT = "application/vnd.ms-fontobject"

	// MIMETypeEPUB defines the MIME type for Electronic publications (EPUB).
	MIMETypeEPUB = "application/epub+zip"

	// MIMETypeGZ defines the MIME type for GZip Compressed Archives.
	MIMETypeGZ = "application/gzip"

	// MIMETypeGIF defines the MIME type for Graphics Interchange Format (GIF).
	MIMETypeGIF = "image/gif"

	// MIMETypeHTML defines the MIME type for HyperText Markup Language (HTML).
	MIMETypeHTML = "text/html"

	// MIMETypeICO defines the MIME type for Icon format.
	MIMETypeICO = "image/vnd.microsoft.icon"

	// MIMETypeICS defines the MIME type for iCalendar format.
	MIMETypeICS = "text/calendar"

	// MIMETypeJAR defines the MIME type for Java Archives (JAR).
	MIMETypeJAR = "application/java-archive"

	// MIMETypeJPEG defines the MIME type for JPEG images.
	MIMETypeJPEG = "image/jpeg"

	// MIMETypeJS defines the MIME type for JavaScript.
	MIMETypeJS = "text/javascript"

	// MIMETypeJSON defines the MIME type for JSON format.
	MIMETypeJSON = "application/json"

	// MIMETypeJSONLD defines the MIME type for JSON-LD format.
	MIMETypeJSONLD = "application/ld+json"

	// MIMETypeMIDI defines the MIME type for Musical Instrument Digital Interface (MIDI).
	MIMETypeMIDI = "audio/midi"

	// MIMETypeMJS defines the MIME type for JavaScript modules.
	MIMETypeMJS = "text/javascript"

	// MIMETypeMP3 defines the MIME type for MP3 audio.
	MIMETypeMP3 = "audio/mpeg"

	// MIMETypeMP4 defines the MIME type for MP4 video.
	MIMETypeMP4 = "video/mp4"

	// MIMETypeMPEG defines the MIME type for MPEG Video.
	MIMETypeMPEG = "video/mpeg"

	// MIMETypeMPKG defines the MIME type for Apple Installer Packages.
	MIMETypeMPKG = "application/vnd.apple.installer+xml"

	// MIMETypeODP defines the MIME type for OpenDocument presentation documents.
	MIMETypeODP = "application/vnd.oasis.opendocument.presentation"

	// MIMETypeODS defines the MIME type for OpenDocument spreadsheet documents.
	MIMETypeODS = "application/vnd.oasis.opendocument.spreadsheet"

	// MIMETypeODT defines the MIME type for OpenDocument text documents.
	MIMETypeODT = "application/vnd.oasis.opendocument.text"

	// MIMETypeOGA defines the MIME type for Ogg audio.
	MIMETypeOGA = "audio/ogg"

	// MIMETypeOGV defines the MIME type for Ogg video.
	MIMETypeOGV = "video/ogg"

	// MIMETypeOGX defines the MIME type for Ogg.
	MIMETypeOGX = "application/ogg"

	// MIMETypeOPUS defines the MIME type for Opus audio in Ogg container.
	MIMETypeOPUS = "audio/ogg"

	// MIMETypeOTF defines the MIME type for OpenType fonts.
	MIMETypeOTF = "font/otf"

	// MIMETypePNG defines the MIME type for Portable Network Graphics.
	MIMETypePNG = "image/png"

	// MIMETypePDF defines the MIME type for Adobe Portable Document Format (PDF).
	MIMETypePDF = "application/pdf"

	// MIMETypePHP defines the MIME type for Hypertext Preprocessor (Personal Home Page).
	MIMETypePHP = "application/x-httpd-php"

	// MIMETypePPT defines the MIME type for Microsoft PowerPoint.
	MIMETypePPT = "application/vnd.ms-powerpoint"

	// MIMETypePPTX defines the MIME type for Microsoft PowerPoint (OpenXML).
	MIMETypePPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation"

	// MIMETypeRAR defines the MIME type for RAR archives.
	MIMETypeRAR = "application/vnd.rar"

	// MIMETypeRTF defines the MIME type for Rich Text Format (RTF).
	MIMETypeRTF = "application/rtf"

	// MIMETypeSH defines the MIME type for Bourne shell scripts.
	MIMETypeSH = "application/x-sh"

	// MIMETypeSVG defines the MIME type for Scalable Vector Graphics (SVG).
	MIMETypeSVG = "image/svg+xml"

	// MIMETypeTAR defines the MIME type for Tape Archives (TAR).
	MIMETypeTAR = "application/x-tar"

	// MIMETypeTIFF defines the MIME type for Tagged Image File Format (TIFF).
	MIMETypeTIFF = "image/tiff"

	// MIMETypeTS defines the MIME type for MPEG transport stream.
	MIMETypeTS = "video/mp2t"

	// MIMETypeTTF defines the MIME type for TrueType Fonts.
	MIMETypeTTF = "font/ttf"

	// MIMETypeTXT defines the MIME type for Plain Text.
	MIMETypeTXT = "text/plain"

	// MIMETypeText is an alias for MIMETypeTXT.
	MIMETypeText = MIMETypeTXT

	// MIMETypePlain is an alias for MIMETypeTXT.
	MIMETypePlain = MIMETypeTXT

	// MIMETypeVSD defines the MIME type for Microsoft Visio.
	MIMETypeVSD = "application/vnd.visio"

	// MIMETypeWAV defines the MIME type for Waveform Audio Format.
	MIMETypeWAV = "audio/wav"

	// MIMETypeWEBA defines the MIME type for WEBM audio.
	MIMETypeWEBA = "audio/webm"

	// MIMETypeWEBM defines the MIME type for WEBM video.
	MIMETypeWEBM = "video/webm"

	// MIMETypeWEBP defines the MIME type for WEBP images.
	MIMETypeWEBP = "image/webp"

	// MIMETypeWOFF defines the MIME type for Web Open Font Format (WOFF).
	MIMETypeWOFF = "font/woff"

	// MIMETypeWOFF2 defines the MIME type for Web Open Font Format (WOFF2).
	MIMETypeWOFF2 = "font/woff2"

	// MIMETypeXHTML defines the MIME type for XHTML.
	MIMETypeXHTML = "application/xhtml+xml"

	// MIMETypeXLS defines the MIME type for Microsoft Excel.
	MIMETypeXLS = "application/vnd.ms-excel"

	// MIMETypeXLSX defines the MIME type for Microsoft Excel (OpenXML).
	MIMETypeXLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

	// MIMETypeXML defines the MIME type for XML.
	MIMETypeXML = "application/xml"

	// MIMETypeXUL defines the MIME type for XUL.
	MIMETypeXUL = "application/vnd.mozilla.xul+xml"

	// MIMETypeZIP defines the MIME type for ZIP archives.
	MIMETypeZIP = "application/zip"

	// MIMEType3GP defines the MIME type for 3GPP audio/video containers.
	MIMEType3GP = "video/3gpp"

	// MIMEType3G2 defines the MIME type for 3GPP2 audio/video containers.
	MIMEType3G2 = "video/3gpp2"

	// MIMEType7Z defines the MIME type for 7-zip archives.
	MIMEType7Z = "application/x-7z-compressed"
)
