package safebrowsingv5

import(
	bolt "go.etcd.io/bbolt"
	"github.com/rs/zerolog"
	"google.golang.org/api/safebrowsing/v5"

)  


func Update(sbc *safebrowsing.Service, conf *Config, logger *zerolog.Logger){

	db, err := bolt.Open(conf.DBPath, 0600, nil)
	if err != nil {
		logger.Warn().Msg("failed to open database, running in no storage real time mode")
	}
	defer db.Close()

}