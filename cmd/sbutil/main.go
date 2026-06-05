package main

import (
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stop-error/safebrowsingv5"
	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {
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

	config := safebrowsingv5.Config  {
		APIKey: "",
		Logger: Logger,
		DBPath: filepath.Dir(executable) + "//" + "safebrowsing.db",
	} 


	sbc, err := safebrowsingv5.NewClient(config, &Logger)
	if err != nil {
		Logger.Error().Err(err).Msg("failed to create safe browsing client!")
		os.Exit(1)
	}

}