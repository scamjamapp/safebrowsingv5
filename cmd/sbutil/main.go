package main

import (
	"os"
	"os/signal"
	"flag"
	"context"
	"path/filepath"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stop-error/safebrowsingv5"
	"gopkg.in/natefinch/lumberjack.v2"
)

var ClientConfig safebrowsingv5.Config 

func main() {

	var (
	apiKeyFlag    = flag.String("apikey", "", "specify your Safe Browsing API key")
	// databaseFlag  = flag.String("db", "", "path to the Safe Browsing database. By default persistent storage is disabled (not recommended).")
	// serverURLFlag = flag.String("server", safebrowsing.DefaultServerURL, "Safebrowsing API server address.")
	// proxyFlag     = flag.String("proxy", "", "proxy to use to connect to the HTTP server")
	)

	flag.Parse()

	if *apiKeyFlag == "" {
		log.Error().Msg("No -apikey specified!")
		os.Exit(1)
	}

	var Logger zerolog.Logger

	executable, err := os.Executable()
	if err != nil {
		log.Warn().Msg("Could not get path of executable file, logs will be console only.")
		Logger = zerolog.New(os.Stdout).With().Caller().Logger()
	} else {
		logDir := filepath.Dir(executable)

		logWriter := &lumberjack.Logger{
        	Filename:   logDir + "//" + "safebrowsingv5.log",
        	MaxSize:    30, // megabytes
        	MaxBackups: 9,
        	MaxAge:     28, // days
        	Compress:   true,
    	}

		Logger = zerolog.New(zerolog.MultiLevelWriter(os.Stdout, logWriter)).With().Caller().Logger()
	}

	conf := safebrowsingv5.Config  {
		APIKey: *apiKeyFlag,
		Logger: Logger,
		DBPath: filepath.Dir(executable) + "//" + "safebrowsing.db",
		RealTimeMode: true,
	} 

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client, err := safebrowsingv5.NewClient(ctx, conf, &Logger)
	if err != nil {
		Logger.Error().Err(err).Msg("failed to create safe browsing client!")
		os.Exit(1)
	}

	Logger.Info().Msg(client.Config.DBPath)

}