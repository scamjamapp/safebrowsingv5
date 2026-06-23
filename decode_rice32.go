package safebrowsingv5

import (
	"errors"

	"github.com/pektezol/bitreader"
	"github.com/rs/zerolog"
)

type riceDecoder32 struct {
	br *bitreader.Reader
	k  int32 // Golomb-Rice parameter
}


func (rd *riceDecoder32) ReadValue32(logger *zerolog.Logger) (uint32, error) {
	var q uint32
	for {
		bit := uint32(rd.br.TryReadBits(1))


		q += bit
		if bit == 0 {
			break
		} 
		if q > 64 {
			err := errors.New("unary prefix exceeds sanity bound")
			logger.Error().Err(err)
			return 0, err
		}
	}

	r := uint32(rd.br.TryReadBits(uint64(rd.k))) 


	return q<<rd.k + r, nil
}


func newRiceDecoder32(br *bitreader.Reader, k int32) *riceDecoder32 {
	return &riceDecoder32{br, k}
}


func decodeRiceIntegers32(delta riceDelta32, logger *zerolog.Logger) ([]uint32, error) {

	if delta.encodedData == nil {
		err := errors.New("missing rice encoded data")
		logger.Error().Err(err)
		return nil, err
	}


	if delta.kParam < 3 || delta.kParam > 30 {
		err := errors.New("invalid k parameter")
		logger.Error().Err(err)
		return nil, err
	}



		values := []uint32{uint32(delta.firstValue)}
		br := bitreader.NewReaderFromBytes(delta.encodedData, true)
		rd := newRiceDecoder32(br, delta.kParam)
		for i := 0; i < int(delta.entriesCount); i++ {
			delta, err := rd.ReadValue32(logger)
			if err != nil {
				logger.Error().Err(err)
				return nil, err
			}
		values = append(values, values[i]+delta)
		}
		if br.TryReadRemainingBits() >= 8 {
		return nil, errors.New("safebrowsing: unconsumed rice encoded data")
		}

	return values, nil
}
