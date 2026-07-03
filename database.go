package safebrowsingv5

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"reflect"
	"io"
	"time"
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
	fetchUpdatePath = "/v5/hashList"
	fetchBatchUpdatePath = "/v5/hashLists:batchGet"
	
)


func BackgroundUpdater(ctx context.Context, client *SafeBrowsingClient, logger *zerolog.Logger) {


	var waitDurationTimer = time.NewTimer(0)
	defer waitDurationTimer.Stop()


	doUpdate := func() time.Duration {
		waitDurationGetChan := make(chan time.Duration, 1)
		go func() {
			Update(ctx, client, waitDurationGetChan, logger)
		}()
		newWaitDuration := <- waitDurationGetChan
		return newWaitDuration
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-waitDurationTimer.C:
			wait := doUpdate()
			if wait < client.Config.UpdatePeriod {
                wait = client.Config.UpdatePeriod
            }
            waitDurationTimer.Reset(wait)
		}
	}

}

func Update(ctx context.Context, client *SafeBrowsingClient, waitDurationGetChan chan time.Duration, logger *zerolog.Logger) error {

	defer close(waitDurationGetChan)
	
	if !client.updateLock.TryLock() {
		logger.Info().Msg("update already in progress, will skip until next update in " + client.Config.UpdatePeriod.String())
		return nil
	}
	defer client.updateLock.Unlock()

	db, err := bolt.Open(client.Config.DBPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		logger.Error().Err(err).Msg("failed to open database!")
		return err
	}	
	logger.Debug().Msg("DBpath is " + client.Config.DBPath)
	defer db.Close()

	response, err := GetUpdatedHashlists(ctx, db, client, logger)
	if err != nil {
		logger.Error().Err(err).Msg("")
		return err
	}

	waitDurations := make([]*safebrowsing.Duration, 0)

	for _, hashlist := range response.HashLists {
		verifyHashlist := hashlist

		if hashlist.PartialUpdate == true {
			err, pendingUpdate := partialUpdate(hashlist, db, logger)
			if err != nil {
				logger.Error().Err(err).Msg("")
    			return err
			}

			for pendingUpdate == true {
				response, err := getPendingUpdate(ctx, client, verifyHashlist, logger)
				if err != nil {
					logger.Error().Err(err).Msg("")
					return err
				}
				if response.PartialUpdate == true {
					err, pendingUpdate = partialUpdate(response, db, logger)
					if err != nil {
						logger.Error().Err(err).Msg("")
    					return err
					}
				} else {
					err, pendingUpdate = fullUpdate(response, db, logger)
					if err != nil {
						logger.Error().Err(err).Msg("")
    					return err
					}
				}
				verifyHashlist  = response
			}
		} else {
			err, _ := fullUpdate(hashlist, db, logger)
			if err != nil {
				logger.Error().Err(err).Msg("")
    			return err
			}

			
		}


		runfullUpdate := false
		if err := db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(hashlist.Name))
			d := b.Bucket([]byte(hashlist.Name + "-hashes"))
			m := b.Bucket([]byte(hashlist.Name + "-metadata"))
			h := sha256.New()
			c := d.Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				h.Write(k)
			}
			checksum := h.Sum(nil)


			switch {
			case bytes.Equal(checksum, verifyHashlist.Sha256Checksum):
				logger.Info().Msg("hashlist " + hashlist.Name + " has passed checksum verification")
				return nil
			case bytes.Equal(nil, verifyHashlist.Sha256Checksum) || len(verifyHashlist.Sha256Checksum) == 0:
				logger.Info().Msg("hashlist " + hashlist.Name + " is nil/empty, will use exisiting checksum")
				savedChecksum := m.Get([]byte("sha256Checksum"))
				if reflect.DeepEqual(savedChecksum, checksum) {
					logger.Info().Msg("hashlist " + hashlist.Name + " has passed checksum verification")
					return nil
				} else if !reflect.DeepEqual(savedChecksum, checksum){
					logger.Warn().Msg("hashlist " + hashlist.Name + " has failed checksum verification, must run full update!")
					runfullUpdate = true
				}
			default:
				logger.Warn().Msg("hashlist " + hashlist.Name + " has failed checksum verification, must run full update!")
				runfullUpdate = true
			}
			return nil

		}); err != nil {
    		return err
		}

		if runfullUpdate == true {
			fullHashlist, err := forceFullUpdate(ctx, client, hashlist, logger)
			if err != nil {
				logger.Error().Err(err).Msg("")
				return err
			}
			err, _ = fullUpdate(fullHashlist, db, logger)
			if err != nil {
				logger.Error().Err(err).Msg("Could not run full update!")
				return err
			}


		} 

		waitDurations = append(waitDurations, hashlist.MinimumWaitDuration)

	}

	var largestWaitDuration time.Duration
	if len(waitDurations) > 0 {
		for _, dur := range waitDurations {
		    result := time.Duration(dur.GetSeconds())*time.Second + time.Duration(dur.GetNanos())*time.Nanosecond
			if result > largestWaitDuration {
				largestWaitDuration = result
			}
		}

		waitDurationGetChan <- largestWaitDuration

		return nil
	}
	logger.Debug().Msg("waitDurations was 0-length or nil")
	return nil
}


func fullUpdate(hashlist *safebrowsing.HashList, db *bolt.DB, logger *zerolog.Logger) (error, bool) {

	var pendingUpdate bool

	if err := db.Update(func(tx *bolt.Tx) error {
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
			switch hashlist.CompressedAdditions.(type) {
				case *safebrowsing.HashList_AdditionsThirtyTwoBytes:
					for _, decodedHash := range decodedHashes.delta256.decodedData {
						buf :=  decodedHash.Bytes32()
						if err := h.Put(buf[:], nil); err != nil {
							logger.Error().Err(err).Msg("")
							return err
						}
					} 
					if err := m.Put([]byte("version"), hashlist.Version); err != nil {
						logger.Error().Err(err).Msg("")
						return err
					}
					if err := m.Put([]byte("sha256Checksum"), hashlist.Sha256Checksum); err != nil {
						logger.Error().Err(err).Msg("")
						return err
					}
				default:
					for _, decodedHash := range decodedHashes.delta32.decodedData {
						var buf [4]byte
						binary.BigEndian.PutUint32(buf[:], decodedHash)
						if err := h.Put(buf[:], nil); err != nil {
							logger.Error().Err(err).Msg("")
							return err
						}
						}
						if err := m.Put([]byte("version"), hashlist.Version); err != nil {
							logger.Error().Err(err).Msg("")
							return err
						}
						if err := m.Put([]byte("sha256Checksum"), hashlist.Sha256Checksum); err != nil {
							logger.Error().Err(err).Msg("")
							return err
					}
			}
		} else {
			logger.Info().Msg("CompressedAdditions for " + hashlist.Name + "is null, nothing to update")
		}
		
		return nil
	}); err != nil {
    		return err, false
		}

	minWait := hashlist.MinimumWaitDuration

	if hashlist.MinimumWaitDuration == nil || (minWait.Seconds == 0 && minWait.Nanos == 0 ) {
		logger.Info().Msg("MinimumWaitDuration is 0, need to run update again for additional data.")
		pendingUpdate = true
	}
	
	return nil, pendingUpdate
}


func partialUpdate(hashlist *safebrowsing.HashList, db *bolt.DB, logger *zerolog.Logger) (error, bool) {

	var pendingUpdate bool

	if err := db.Update(func(tx *bolt.Tx) error {
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
				var toDelete [][]byte
				removalSet := make(map[uint32]struct{}, len(decodedIndices.decodedData))
				for _, idx := range decodedIndices.decodedData {
					removalSet[idx] = struct{}{}
				}

				for k, _ := c.First(); k != nil; k, _ = c.Next() {
					if _, shouldRemove := removalSet[currentIdx]; shouldRemove {
						kc := append([]byte(nil), k...)
						toDelete = append(toDelete, kc)
					}
					currentIdx++
				}
				for _, k := range toDelete {
					if err := h.Delete(k); err != nil {
						logger.Error().Err(err).Msg("")
						return err
					}
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
				switch hashlist.CompressedAdditions.(type) {
					case *safebrowsing.HashList_AdditionsThirtyTwoBytes:
						for _, decodedHash := range decodedHashes.delta256.decodedData {
							buf :=  decodedHash.Bytes32()
							if err := h.Put(buf[:], nil); err != nil {
								logger.Error().Err(err).Msg("")
								return err
							}
						} 
						if err := m.Put([]byte("version"), hashlist.Version); err != nil {
							logger.Error().Err(err).Msg("")
							return err
						}
						if err := m.Put([]byte("sha256Checksum"), hashlist.Sha256Checksum); err != nil {
							logger.Error().Err(err).Msg("")
							return err
						}
					default:
						for _, decodedHash := range decodedHashes.delta32.decodedData {
							var buf [4]byte
							binary.BigEndian.PutUint32(buf[:], decodedHash)
							if err := h.Put(buf[:], nil); err != nil {
								logger.Error().Err(err).Msg("")
								return err
							}
						}
						if err := m.Put([]byte("version"), hashlist.Version); err != nil {
							logger.Error().Err(err).Msg("")
							return err
						}
						if err := m.Put([]byte("sha256Checksum"), hashlist.Sha256Checksum); err != nil {
							logger.Error().Err(err).Msg("")
							return err
						}
				}

			} else {
				logger.Info().Msg("CompressedAdditions for " + hashlist.Name + "is null, nothing to update")
			}

		} else {
			err := errors.New("bucket " + hashlist.Name + " does not exist, but PartialUpdate=true!")
			logger.Error().Err(err).Msg("")
			return err
		} 
		return nil
	}); err != nil {
    		return err, false
		}


	minWait := hashlist.MinimumWaitDuration

	if hashlist.MinimumWaitDuration == nil || (minWait.Seconds == 0 && minWait.Nanos == 0 ) {
		logger.Info().Msg("MinimumWaitDuration is 0, need to run update again for additional data.")
		pendingUpdate = true
	}

	return nil, pendingUpdate
}



func GetUpdatedHashlists(ctx context.Context, db *bolt.DB, client  *SafeBrowsingClient, logger *zerolog.Logger) (*safebrowsing.BatchGetHashListsResponse, error) {

	queryParams, err := getQueryParams(db, client, logger)
	if err != nil {
		logger.Error().Err(err).Msg("")
		return nil, err
	}


	parsedUrl, err := url.Parse(client.Config.ServerURL)
	if err != nil {
		logger.Error().Err(err).Msg("failed to parse ServerURL!")
		return nil, err
	}


	parsedUrl = parsedUrl.JoinPath(fetchBatchUpdatePath)
	logger.Info().Msg(parsedUrl.String())

    parsedUrl.RawQuery = queryParams.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", parsedUrl.String(), nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create new http request!")
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-protobuf")


	resp, err := client.HttpClient.Do(req)
	if err != nil {
		logger.Warn().Err(err).Msg("http request failed in transit!")
		return nil, err
	}
	defer resp.Body.Close()


	if resp.StatusCode != 200 {
		err := errors.New("http request status code is " + strconv.Itoa(resp.StatusCode) + "!")
		logger.Error().Err(err).Msg("")
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error().Err(err).Msg("")
		return nil, err
	}


	var response safebrowsing.BatchGetHashListsResponse
	if err := proto.Unmarshal(body, &response); err != nil {
		logger.Error().Err(err).Msg("failed to unmarshal response")
    	return nil, err
	}

	return &response, nil
}


func getPendingUpdate(ctx context.Context, client  *SafeBrowsingClient, hashlist *safebrowsing.HashList, logger *zerolog.Logger) (*safebrowsing.HashList, error) {

	queryParams := url.Values{}
    queryParams.Add("key", client.Config.APIKey)

	if hashlist.PartialUpdate == false {
			queryParams.Add("names", hashlist.Name)
		} else {
			version64str := base64.URLEncoding.EncodeToString(hashlist.Version)
			queryParams.Add("version", version64str)
			queryParams.Add("names", hashlist.Name)
		}

	parsedUrl, err := url.Parse(client.Config.ServerURL)
	if err != nil {
		logger.Error().Err(err).Msg("failed to parse ServerURL!")
		return nil, err
	}


	parsedUrl = parsedUrl.JoinPath(fetchBatchUpdatePath)
	logger.Info().Msg(parsedUrl.String())

    parsedUrl.RawQuery = queryParams.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", parsedUrl.String(), nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create new http request!")
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-protobuf")


	resp, err := client.HttpClient.Do(req)
	if err != nil {
		logger.Warn().Err(err).Msg("http request failed in transit!")
		return nil, err
	}
	defer resp.Body.Close()


	if resp.StatusCode != 200 {
		err := errors.New("http request status code is " + strconv.Itoa(resp.StatusCode) + "!")
		logger.Error().Err(err).Msg("")
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error().Err(err).Msg("")
		return nil, err
	}


	var response safebrowsing.BatchGetHashListsResponse
	if err := proto.Unmarshal(body, &response); err != nil {
		logger.Error().Err(err).Msg("failed to unmarshal response")
    	return nil, err
	}

	if len(response.HashLists) == 0{
		err := errors.New("HashLists in GetPendingUpdate is empty!")
		logger.Error().Err(err).Msg("")
		return nil, err
	}

	return response.HashLists[0], nil
}


func getQueryParams(db *bolt.DB, client *SafeBrowsingClient, logger *zerolog.Logger) (url.Values, error) {

	

	queryParams := url.Values{}
    queryParams.Add("key", client.Config.APIKey)
	
	for _, hashlist := range client.Config.HashLists {
		
		var version []byte
		nameOnly := false

		if err := db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(hashlist))
			if b == nil {
				logger.Debug().Msg("hashlist bucket is nil!")
				nameOnly = true
			} else if m := b.Bucket([]byte(hashlist + "-metadata"));  m == nil {
				logger.Debug().Msg(hashlist + "-metadata" + " does not exist!")
				nameOnly = true
			} else if version = m.Get([]byte("version")); version == nil {
				logger.Debug().Msg("version data does not exist!")
				nameOnly = true 
			} else {
    			version = append([]byte(nil), version...)
			}
			
			return nil
	 	}) ; err != nil {
    		return nil, err 
		}


		if nameOnly == true {
			queryParams.Add("names", hashlist)
		} else {
			version64str := base64.URLEncoding.EncodeToString(version)
			queryParams.Add("version", version64str)
			queryParams.Add("names", hashlist)
		}

	}

	return queryParams, nil
}

func forceFullUpdate(ctx context.Context, client  *SafeBrowsingClient, hashlist *safebrowsing.HashList, logger *zerolog.Logger) (*safebrowsing.HashList, error) {
	queryParams := url.Values{}
    queryParams.Add("key", client.Config.APIKey)

	parsedUrl, err := url.Parse(client.Config.ServerURL)
	if err != nil {
		logger.Error().Err(err).Msg("failed to parse ServerURL!")
		return nil, err
	}

	parsedUrl = parsedUrl.JoinPath(fetchUpdatePath)
	parsedUrl = parsedUrl.JoinPath(hashlist.Name)
	logger.Info().Msg(parsedUrl.String())

    parsedUrl.RawQuery = queryParams.Encode()


	req, err := http.NewRequestWithContext(ctx, "GET", parsedUrl.String(), nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create new http request!")
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-protobuf")


	resp, err := client.HttpClient.Do(req)
	if err != nil {
		logger.Warn().Err(err).Msg("http request failed in transit!")
		return nil, err
	}
	defer resp.Body.Close()


	if resp.StatusCode != 200 {
		err := errors.New("http request status code is " + strconv.Itoa(resp.StatusCode) + "!")
		logger.Error().Err(err).Msg("")
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error().Err(err).Msg("")
		return nil, err
	}


	var response safebrowsing.HashList
	if err := proto.Unmarshal(body, &response); err != nil {
		logger.Error().Err(err).Msg("failed to unmarshal response")
    	return nil, err
	}

	return &response, nil
}