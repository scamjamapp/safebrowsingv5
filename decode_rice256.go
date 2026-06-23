package safebrowsingv5

import (
	"errors"
	"github.com/pektezol/bitreader"
	"github.com/rs/zerolog"
	"github.com/holiman/uint256"
)

type riceDecoder256 struct {
	br *bitreader.Reader
	k  int32 // Golomb-Rice parameter
}


func (rd *riceDecoder256) ReadValue256(logger *zerolog.Logger) (*uint256.Int, error) {
	q := new(uint256.Int)
	one := uint256.NewInt(1)
	limit := uint256.NewInt(256)

	for {
		bit := uint256.NewInt(rd.br.TryReadBits(1))
		


		q.Add(q, one)
		if bit.IsZero() {
			break
		} 
		if q.Gt(limit) {
			err := errors.New("unary prefix exceeds sanity bound")
			logger.Error().Err(err).Msg("")
			return nil, err
		}
	}

	
	k1, k2, k3 := uint64(64), uint64(64), uint64(64)
	k4 := uint64(rd.k) - 192
	r := &uint256.Int{
	(rd.br.TryReadBits(k1)),  
	(rd.br.TryReadBits(k2)),  
	(rd.br.TryReadBits(k3)),   
	(rd.br.TryReadBits(k4)),   
	}


	result := new(uint256.Int)
	result.Lsh(q, uint(rd.k))
	result.Add(result, r)
	return result, nil
}


func newRiceDecoder256(br *bitreader.Reader, k int32) *riceDecoder256 {
	return &riceDecoder256{br, k}
}


func decodeRiceIntegers256(delta riceDelta256, logger *zerolog.Logger) ([]*uint256.Int, error) {

	if delta.encodedData == nil {
		err := errors.New("missing rice encoded data")
		logger.Error().Err(err)
		return nil, err
	}


	if delta.kParam < 227 || delta.kParam > 254 {
		err := errors.New("invalid k parameter")
		logger.Error().Err(err)
		return nil, err
	}


	firstValue := &uint256.Int{
	delta.firValFourPar,  
	delta.firValThirPar,  
	delta.firValSecPar,   
	delta.firValFirPar,   
	}


		values := []*uint256.Int{firstValue}
		br := bitreader.NewReaderFromBytes(delta.encodedData, true)
		rd := newRiceDecoder256(br, delta.kParam)
		for i := 0; i < int(delta.entriesCount); i++ {
			d, err := rd.ReadValue256(logger)
			if err != nil {
				logger.Error().Err(err).Msg("")
				return nil, err
			}
			bit := new(uint256.Int)
			bit.Add(values[i], d)
			values = append(values, bit)
		}
		if br.TryReadRemainingBits() >= 256 {
		return nil, errors.New("safebrowsing: unconsumed rice encoded data")
		}

	return values, nil
}
