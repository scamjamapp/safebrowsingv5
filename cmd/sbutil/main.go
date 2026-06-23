package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"context"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stop-error/safebrowsingv5"
	"gopkg.in/natefinch/lumberjack.v2"
)

var ClientConfig safebrowsingv5.Config 

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

	conf := safebrowsingv5.Config  {
		APIKey: "",
		Logger: Logger,
		DBPath: filepath.Dir(executable) + "//" + "safebrowsing.db",
		RealTimeMode: true,
	} 


	client, err := safebrowsingv5.NewClient(conf, &Logger)
	if err != nil {
		Logger.Error().Err(err).Msg("failed to create safe browsing client!")
		os.Exit(1)
	}

	updateContext, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	safebrowsingv5.Update(client, updateContext, &Logger) //goroutine loop based off of wait duration

}