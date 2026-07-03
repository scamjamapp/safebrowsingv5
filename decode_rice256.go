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
		bit256, err := rd.br.ReadBits(1)
		if err != nil {
			logger.Error().Err(err).Msg("could not read part of 256-bit value!")
			return nil, err
		}
		bit := uint256.NewInt(bit256)
		if bit.IsZero() {
        	break
    	}
		q.Add(q, one)

		if q.Gt(limit) {
			err := errors.New("unary prefix exceeds sanity bound")
			logger.Error().Err(err).Msg("")
			return nil, err
		}
	}

	

	remainder := uint64(rd.k) - 192


	limb0, err := rd.br.ReadBits(64)
	if err != nil {
		logger.Error().Err(err).Msg("could not read part of 256-bit value!")
		return nil, err
	}
	limb1, err := rd.br.ReadBits(64)
	if err != nil {
		logger.Error().Err(err).Msg("could not read part of 256-bit value!")
		return nil, err
	}
	limb2, err := rd.br.ReadBits(64)
	if err != nil {
		logger.Error().Err(err).Msg("could not read part of 256-bit value!")
		return nil, err
	}
	limb3, err := rd.br.ReadBits(remainder)
	if err != nil {
		logger.Error().Err(err).Msg("could not read part of 256-bit value!")
		return nil, err
	}
	r := &uint256.Int{limb0, limb1, limb2, limb3}


	result := new(uint256.Int)
	result.Lsh(q, uint(rd.k))
	result.Add(result, r)
	return result, nil
}


func newRiceDecoder256(br *bitreader.Reader, k int32) *riceDecoder256 {
	return &riceDecoder256{br, k}
}


func decodeRiceIntegers256(delta riceDelta256, logger *zerolog.Logger) ([]*uint256.Int, error) {

	firstValue := &uint256.Int{
		delta.firValFourPar, delta.firValThirPar, delta.firValSecPar, delta.firValFirPar,
	}

	if delta.entriesCount == 0 {
		return []*uint256.Int{firstValue}, nil
	}

	if delta.encodedData == nil {
		err := errors.New("missing rice encoded data")
		logger.Error().Err(err).Msg("")
		return nil, err
	} 


	if delta.kParam < 227 || delta.kParam > 254 {
		err := errors.New("invalid k parameter")
		logger.Error().Err(err).Msg("")
		return nil, err
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
		remaining, err := br.ReadRemainingBits()
		if err != nil {
    		return nil, err
		}
		if remaining >= 8 {
		return nil, errors.New("unconsumed rice encoded data!")
		}

	return values, nil
}
