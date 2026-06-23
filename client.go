package safebrowsingv5

import (
	"errors"
	"net/http"
	"time"
	"crypto/tls"
	"os"
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

	boltDir string


}

type SafeBrowsingClient struct {

	HttpClient http.Client

	Config Config

}

func (c Config) copy() Config {
	c2 := c
	c2.HashLists = append([]string(nil), c.HashLists...)
	return c2
}



func (c *Config) setDefaults() (bool) {
	if c.ServerURL == "" {
		c.ServerURL = DefaultServerURL
	}
	if len(c.HashLists) == 0 {
		c.HashLists = DefaultHashLists
		if c.RealTimeMode == true {
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



func NewClient(conf Config, logger *zerolog.Logger) (*SafeBrowsingClient, error) {

	conf = conf.copy()
	if !conf.setDefaults() {
		err := errors.New("invalid configuration")
		logger.Error().Err(err).Msg("")
		return nil, err
	}

	executable, err := os.Executable()
	if err != nil {
		logger.Error().Err(err).Msg("filed to get path of exec file!")
		return nil, err
	}
	
	conf.boltDir = filepath.Dir(executable)
	conf.boltDir = conf.boltDir + "safebrowsing.db"

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
	
	return &sbc, nil

}

