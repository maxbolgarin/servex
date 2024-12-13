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

		if c.CertFile == "" || c.KeyFile == "" {
			return errors.New("cert_file and key_file should be set")
		}
	}

	return nil
}

func parseOptions(opts []Option) Options {
	op := Options{}
	for _, o := range opts {
		o(&op)
	}
	return op
}

const (
	// AAC audio
	MIMETypeAAC = "audio/aac"

	// AbiWord document
	MIMETypeABW = "application/x-abiword"

	// Animated Portable Network Graphics (APNG)
	MIMETypeAPNG = "image/apng"

	// Archive document (multiple files embedded)
	MIMETypeARC = "application/x-freearc"

	// AVIF image
	MIMETypeAVIF = "image/avif"

	// AVI: Audio Video Interleave
	MIMETypeAVI = "video/x-msvideo"

	// Amazon Kindle eBook format
	MIMETypeAZW = "application/vnd.amazon.ebook"

	// Any kind of binary data
	MIMETypeBIN = "application/octet-stream"

	// Windows OS/2 Bitmap Graphics
	MIMETypeBMP = "image/bmp"

	// BZip archive
	MIMETypeBZ = "application/x-bzip"

	// BZip2 archive
	MIMETypeBZ2 = "application/x-bzip2"

	// CD audio
	MIMETypeCDA = "application/x-cdf"

	// C-Shell script
	MIMETypeCSH = "application/x-csh"

	// Cascading Style Sheets (CSS)
	MIMETypeCSS = "text/css"

	// Comma-separated values (CSV)
	MIMETypeCSV = "text/csv"

	// Microsoft Word
	MIMETypeDOC = "application/msword"

	// Microsoft Word (OpenXML)
	MIMETypeDOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

	// MS Embedded OpenType fonts
	MIMETypeEOT = "application/vnd.ms-fontobject"

	// Electronic publication (EPUB)
	MIMETypeEPUB = "application/epub+zip"

	// GZip Compressed Archive
	MIMETypeGZ = "application/gzip"

	// Graphics Interchange Format (GIF)
	MIMETypeGIF = "image/gif"

	// HyperText Markup Language (HTML)
	MIMETypeHTML = "text/html"

	// Icon format
	MIMETypeICO = "image/vnd.microsoft.icon"

	// iCalendar format
	MIMETypeICS = "text/calendar"

	// Java Archive (JAR)
	MIMETypeJAR = "application/java-archive"

	// JPEG images
	MIMETypeJPEG = "image/jpeg"

	// JavaScript
	MIMETypeJS = "text/javascript"

	// JSON format
	MIMETypeJSON = "application/json"

	// JSON-LD format
	MIMETypeJSONLD = "application/ld+json"

	// Musical Instrument Digital Interface (MIDI)
	MIMETypeMIDI = "audio/midi"

	// JavaScript module
	MIMETypeMJS = "text/javascript"

	// MP3 audio
	MIMETypeMP3 = "audio/mpeg"

	// MP4 video
	MIMETypeMP4 = "video/mp4"

	// MPEG Video
	MIMETypeMPEG = "video/mpeg"

	// Apple Installer Package
	MIMETypeMPKG = "application/vnd.apple.installer+xml"

	// OpenDocument presentation document
	MIMETypeODP = "application/vnd.oasis.opendocument.presentation"

	// OpenDocument spreadsheet document
	MIMETypeODS = "application/vnd.oasis.opendocument.spreadsheet"

	// OpenDocument text document
	MIMETypeODT = "application/vnd.oasis.opendocument.text"

	// Ogg audio
	MIMETypeOGA = "audio/ogg"

	// Ogg video
	MIMETypeOGV = "video/ogg"

	// Ogg
	MIMETypeOGX = "application/ogg"

	// Opus audio in Ogg container
	MIMETypeOPUS = "audio/ogg"

	// OpenType font
	MIMETypeOTF = "font/otf"

	// Portable Network Graphics
	MIMETypePNG = "image/png"

	// Adobe Portable Document Format (PDF)
	MIMETypePDF = "application/pdf"

	// Hypertext Preprocessor (Personal Home Page)
	MIMETypePHP = "application/x-httpd-php"

	// Microsoft PowerPoint
	MIMETypePPT = "application/vnd.ms-powerpoint"

	// Microsoft PowerPoint (OpenXML)
	MIMETypePPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation"

	// RAR archive
	MIMETypeRAR = "application/vnd.rar"

	// Rich Text Format (RTF)
	MIMETypeRTF = "application/rtf"

	// Bourne shell script
	MIMETypeSH = "application/x-sh"

	// Scalable Vector Graphics (SVG)
	MIMETypeSVG = "image/svg+xml"

	// Tape Archive (TAR)
	MIMETypeTAR = "application/x-tar"

	// Tagged Image File Format (TIFF)
	MIMETypeTIFF = "image/tiff"

	// MPEG transport stream
	MIMETypeTS = "video/mp2t"

	// TrueType Font
	MIMETypeTTF = "font/ttf"

	// Plain Text
	MIMETypeTXT = "text/plain"

	// Plain Text
	MIMETypeText = MIMETypeTXT

	// Plain Text
	MIMETypePlain = MIMETypeTXT

	// Microsoft Visio
	MIMETypeVSD = "application/vnd.visio"

	// Waveform Audio Format
	MIMETypeWAV = "audio/wav"

	// WEBM audio
	MIMETypeWEBA = "audio/webm"

	// WEBM video
	MIMETypeWEBM = "video/webm"

	// WEBP image
	MIMETypeWEBP = "image/webp"

	// Web Open Font Format (WOFF)
	MIMETypeWOFF = "font/woff"

	// Web Open Font Format (WOFF2)
	MIMETypeWOFF2 = "font/woff2"

	// XHTML
	MIMETypeXHTML = "application/xhtml+xml"

	// Microsoft Excel
	MIMETypeXLS = "application/vnd.ms-excel"

	// Microsoft Excel (OpenXML)
	MIMETypeXLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

	// XML
	MIMETypeXML = "application/xml"

	// XUL
	MIMETypeXUL = "application/vnd.mozilla.xul+xml"

	// ZIP archive
	MIMETypeZIP = "application/zip"

	// 3GPP audio/video container
	MIMEType3GP = "video/3gpp"

	// 3GPP2 audio/video container
	MIMEType3G2 = "video/3gpp2"

	// 7-zip archive
	MIMEType7Z = "application/x-7z-compressed"
)
