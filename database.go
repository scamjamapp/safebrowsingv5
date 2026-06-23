package safebrowsingv5

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/rs/zerolog"
	safebrowsing "github.com/stop-error/safebrowsingv5/internal/safebrowsing_pb"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)  


const (
	findHashPath    = "/v5/hashes:search"
	fetchUpdatePath = "/v5/hashLists:batchGet"
	
)


func Update(client *SafeBrowsingClient, ctx context.Context, logger *zerolog.Logger) error {

	db, err := bolt.Open(client.Config.boltDir, 0600, nil)
	logger.Debug().Msg("boltDir is " + client.Config.boltDir)
	if err != nil {
		logger.Error().Err(err).Msg("failed to open database!")
		return err
	}	
	defer db.Close()

	queryParams := getQueryParams(db, client, logger)


	parsedUrl, err := url.Parse(client.Config.ServerURL)
	if err != nil {
		logger.Error().Err(err).Msg("failed to parse ServerURL!")
		return err
	}


	parsedUrl = parsedUrl.JoinPath(fetchUpdatePath)
	logger.Info().Msg(parsedUrl.String())

    parsedUrl.RawQuery = queryParams.Encode()


	req, err := http.NewRequestWithContext(ctx, "GET", parsedUrl.String(), nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create new http request!")
		return err
	}
	req.Header.Add("Content-Type", "application/x-protobuf")


	resp, err := client.HttpClient.Do(req)
	if err != nil {
		logger.Warn().Err(err).Msg("http request failed in transit!")
		return err
	}


	if resp.StatusCode != 200 {
		err := errors.New("http request status code is " + strconv.Itoa(resp.StatusCode) + "!")
		logger.Error().Err(err).Msg("")
		return err
	}

	body, err := io.ReadAll(resp.Body)


	var response safebrowsing.BatchGetHashListsResponse
	if err := proto.Unmarshal(body, &response); err != nil {
		logger.Error().Err(err).Msg("failed to unmarshal response")
    	return err
	}

	 //TODO: MinimumWaitDuration

	 for _, hashlist := range response.HashLists {

		if hashlist.PartialUpdate == true {
			partialUpdate(hashlist, db, logger)
			if err != nil {
				logger.Error().Err(err).Msg("")
    			return err
			}
		} else {
			fullUpdate(hashlist, db, logger)
			if err != nil {
				logger.Error().Err(err).Msg("")
    			return err
			}
		}
	 }
	return nil
}


func fullUpdate(hashlist *safebrowsing.HashList, db *bolt.DB, logger *zerolog.Logger) error {
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(hashlist.Name))
		if b != nil {
			logger.Info().Msg("bucket " + hashlist.Name + " exists, but PartialUpdate=false so it will be deleted.")
			err := tx.DeleteBucket([]byte(hashlist.Name))
			if err != nil {
				logger.Error().Err(err).Msg("failed to delete bucket " + hashlist.Name)
				return err
			}
			bnew, err := tx.CreateBucket([]byte(hashlist.Name))
			if err != nil {
				logger.Error().Err(err).Msg("failed to create bucket " + hashlist.Name)
				return err
			}
			_, err = bnew.CreateBucket([]byte(hashlist.Name + "-hashes"))
			if err != nil {
				logger.Error().Err(err).Msg("")
				return err
			}
			_, err = bnew.CreateBucket([]byte(hashlist.Name + "-metadata"))
			if err != nil {
				logger.Error().Err(err).Msg("")
				return err
			}
		} else {
			logger.Info().Msg("bucket " + hashlist.Name + " does not exist, but PartialUpdate=false so it was getting deleted anyways.")
			_, err := tx.CreateBucket([]byte(hashlist.Name))
			if err != nil {
				logger.Error().Err(err).Msg("failed to create bucket " + hashlist.Name)
				return err
			}
			bnew := tx.Bucket([]byte(hashlist.Name))
			_, err = bnew.CreateBucket([]byte( hashlist.Name + "-hashes"))
			if err != nil {
				logger.Error().Err(err).Msg("")
				return err
			}
			_, err = bnew.CreateBucket([]byte(hashlist.Name + "-metadata"))
			if err != nil {
				logger.Error().Err(err).Msg("")
				return err
			}
		}

		b = tx.Bucket([]byte(hashlist.Name))
		h := b.Bucket([]byte(hashlist.Name + "-hashes")) 
		m := b.Bucket([]byte(hashlist.Name + "-metadata"))
		
		if hashlist.CompressedAdditions != nil {
			decodedHashes, err := decodeRiceAdditions(hashlist, logger)
			if err != nil {
				logger.Error().Err(err).Msg("")
				return err
			}
			if hashlist.Name == "gc-32b" {
				for _, decodedHash := range decodedHashes.delta256.decodedData {
					buf :=  decodedHash.Bytes32()
					if err := h.Put(buf[:], nil); err != nil {
						logger.Error().Err(err).Msg("")
						return err
					}
				} 
				m.Put([]byte("version"), hashlist.Version)
				m.Put([]byte("sha256Checksum"), hashlist.Sha256Checksum)
			} else {
				for _, decodedHash := range decodedHashes.delta32.decodedData {
					var buf [4]byte
					binary.BigEndian.PutUint32(buf[:], decodedHash)
					if err := h.Put(buf[:], nil); err != nil {
						logger.Error().Err(err).Msg("")
						return err
					}
				}
				m.Put([]byte("version"), hashlist.Version)
				m.Put([]byte("sha256Checksum"), hashlist.Sha256Checksum)
			}

		} else {
			logger.Info().Msg("CompressedAdditions for " + hashlist.Name + "is null, nothing to update")
		}
		
		return nil
	})
	
	return nil
}


func partialUpdate(hashlist *safebrowsing.HashList, db *bolt.DB, logger *zerolog.Logger) error {
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(hashlist.Name))
		if b != nil {
			logger.Info().Msg("bucket " + hashlist.Name + " exists, running partial update")
			b = tx.Bucket([]byte(hashlist.Name))
			h := b.Bucket([]byte(hashlist.Name + "-hashes")) 
			m := b.Bucket([]byte(hashlist.Name + "-metadata"))
			if hashlist.CompressedRemovals != nil {
				decodedIndices, err := decodeRiceRemovals(hashlist, logger)
				if err != nil {
					logger.Error().Err(err).Msg("")
					return err
				}
				c := h.Cursor()
				var currentIdx uint32 = 0
				removalSet := make(map[uint32]struct{}, len(decodedIndices.decodedData))
				for _, idx := range decodedIndices.decodedData {
					removalSet[idx] = struct{}{}
				}

				for k, _ := c.First(); k != nil; k, _ = c.Next() {
					if _, shouldRemove := removalSet[currentIdx]; shouldRemove {
						if err := c.Delete(); err != nil {
							logger.Error().Err(err).Msg("")
							return err
						}
					}
					currentIdx++
				}
			} else {
				logger.Info().Msg("CompressedRemovals for " + hashlist.Name + "is null, nothing to update")
			}

			if hashlist.CompressedAdditions != nil {
				decodedHashes, err := decodeRiceAdditions(hashlist, logger)
				if err != nil {
					logger.Error().Err(err).Msg("")
					return err
				}
				if hashlist.Name == "gc-32b" {
					for _, decodedHash := range decodedHashes.delta256.decodedData {
						buf :=  decodedHash.Bytes32()
						if err := h.Put(buf[:], nil); err != nil {
							logger.Error().Err(err).Msg("")
							return err
						}
					} 
					m.Put([]byte("version"), hashlist.Version)
					m.Put([]byte("sha256Checksum"), hashlist.Sha256Checksum)
				} else {
					for _, decodedHash := range decodedHashes.delta32.decodedData {
						var buf [4]byte
						binary.BigEndian.PutUint32(buf[:], decodedHash)
						if err := h.Put(buf[:], nil); err != nil {
							logger.Error().Err(err).Msg("")
							return err
						}
					}
					m.Put([]byte("version"), hashlist.Version)
					m.Put([]byte("sha256Checksum"), hashlist.Sha256Checksum)
				}

			} else {
				logger.Info().Msg("CompressedAdditions for " + hashlist.Name + "is null, nothing to update")
			}

		} else {
			logger.Warn().Msg("bucket " + hashlist.Name + " does not exist, but PartialUpdate=true! must run full update!")
			err := fullUpdate(hashlist, db, logger)
			if err != nil {
				logger.Error().Err(err).Msg("could not run full update!")
				return err
			}
		} 
		return nil
	})
return nil
}


func getQueryParams(db *bolt.DB, client *SafeBrowsingClient, logger *zerolog.Logger) (url.Values) {

	var nameOnly bool
	var version []byte

	queryParams := url.Values{}
    queryParams.Add("key", client.Config.APIKey)
	
	for _, hashlist := range client.Config.HashLists {

		db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(hashlist))
			if b == nil {
				logger.Debug().Msg("b is nil!")
				nameOnly = true
			} else if m := b.Bucket([]byte(hashlist + "-metadata"));  m == nil {
				logger.Debug().Msg(hashlist + "-metadata" + " does not exist!")
				nameOnly = true
			} else if version = m.Get([]byte("version")); version == nil {
				logger.Debug().Msg("version data does not exist!")
				nameOnly = true 
			}
			
			return nil
	 	})


		if nameOnly == true {
			queryParams.Add("names", hashlist)
		} else {
			version64str := base64.URLEncoding.EncodeToString(version)
			queryParams.Add("version", version64str)
			queryParams.Add("names", hashlist)
		}

	}

	return queryParams
}