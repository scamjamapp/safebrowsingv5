package safebrowsingv5

import (
	"errors"
	"net/http"
	"time"
	"crypto/tls"
	"os"
	"context"
	"sync"
	"slices"
	"path/filepath"
	"github.com/rs/zerolog"
)



const (
	DefaultServerURL = "https://safebrowsing.googleapis.com"

	DefaultUpdatePeriod = 30 * time.Minute

	DefaultRequestTimeout = time.Minute
)



var DefaultHashLists = []string{"se-4b", "mw-4b", "uws-4b", "pha-4b"}



type Config struct {
	// ServerURL is the URL for the Safe Browsing API server.
	// If empty, it defaults to DefaultServerURL.
	ServerURL string

	// ProxyURL is the URL of the proxy to use for all requests.
	// If empty, the underlying library uses $HTTP_PROXY environment variable.
	ProxyURL string

	// APIKey is the key used to authenticate with the Safe Browsing API
	// service. This field is required.
	APIKey string

	// DBPath is a path to a persistent database file.
	// If empty, SafeBrowser operates in a non-persistent manner.
	// This means that blacklist results will not be cached beyond the lifetime
	// of the SafeBrowser object.
	DBPath string

	// UpdatePeriod determines how often we update the internal list database.
	// If zero value, it defaults to DefaultUpdatePeriod.
	UpdatePeriod time.Duration

	// ThreatLists determines which threat lists that SafeBrowser should
	// subscribe to. The threats reported by LookupURLs will only be ones that
	// are specified by this list.
	// If empty, it defaults to DefaultThreatLists.
	HashLists []string

	// RequestTimeout determines the timeout value for the http client.
	RequestTimeout time.Duration

	// Logger is an io.Writer that allows SafeBrowser to write debug information
	// intended for human consumption.
	// If empty, no logs will be written.
	Logger zerolog.Logger

	RealTimeMode bool
}

type SafeBrowsingClient struct {

	HttpClient http.Client

	Config Config

	updateLock sync.Mutex

}

func (c Config) copy() Config {
	c2 := c
	c2.HashLists = append([]string(nil), c.HashLists...)
	return c2
}



func (c *Config) setDefaults(logger *zerolog.Logger) (bool) {
	if c.ServerURL == "" {
		c.ServerURL = DefaultServerURL
	}
	if c.DBPath == "" {
		executable, err := os.Executable()
		if err != nil {
			logger.Error().Err(err).Msg("failed to get root of exec file!")
			return false
		}
		d := filepath.Dir(executable)
		c.DBPath = filepath.Join(d, "safebrowsing.db")

	}
	if len(c.HashLists) == 0 {
		c.HashLists = DefaultHashLists
	}
	if c.RealTimeMode == true {
		if !slices.Contains(c.HashLists, "gc-32b") {
			c.HashLists = append(c.HashLists, "gc-32b")
			}
		}
	if c.UpdatePeriod <= 0 {
		c.UpdatePeriod = DefaultUpdatePeriod
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = DefaultRequestTimeout
	}
	
	return true
	
	
}



func NewClient(ctx context.Context, conf Config, logger *zerolog.Logger) (*SafeBrowsingClient, error) {

	conf = conf.copy()
	if !conf.setDefaults(logger) {
		err := errors.New("invalid configuration")
		logger.Error().Err(err).Msg("")
		return nil, err
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	sbc := SafeBrowsingClient{
		HttpClient: http.Client{
			Timeout: conf.RequestTimeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		Config: conf,
	}

	
	go BackgroundUpdater(ctx, &sbc, logger)
	
	return &sbc, nil

}

