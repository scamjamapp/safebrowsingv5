package safebrowsingv5

import (
	"errors"
	"github.com/rs/zerolog"
	safebrowsing "github.com/stop-error/safebrowsingv5/internal/safebrowsing_pb"
	"github.com/holiman/uint256"
)

type riceDelta struct {
	delta32 riceDelta32
	delta256 riceDelta256
}

type riceDelta32 struct {
	encodedData  []byte
	decodedData []uint32
	kParam int32
	entriesCount int32

	firstValue uint32
}

type riceDelta256 struct {
	encodedData  []byte
	decodedData []*uint256.Int
	kParam int32
	entriesCount int32

	firValFirPar uint64
	firValSecPar uint64
	firValThirPar uint64
	firValFourPar uint64
}


func decodeRiceAdditions(hashlist *safebrowsing.HashList, logger *zerolog.Logger) (riceDelta, error) {

	var delta32 riceDelta32
	var delta256 riceDelta256


	switch add := hashlist.CompressedAdditions.(type) {
	case *safebrowsing.HashList_AdditionsFourBytes:
		delta32.encodedData = add.AdditionsFourBytes.EncodedData
		delta32.kParam = add.AdditionsFourBytes.RiceParameter
		delta32.entriesCount = add.AdditionsFourBytes.EntriesCount
		delta32.firstValue = add.AdditionsFourBytes.FirstValue
		var err error
		delta32.decodedData, err = decodeRiceIntegers32(delta32, logger)
		if err != nil {
			var errRiceDelta riceDelta
			return errRiceDelta, err
		}
	case  *safebrowsing.HashList_AdditionsThirtyTwoBytes:
		delta256.encodedData = add.AdditionsThirtyTwoBytes.EncodedData
		delta256.kParam = add.AdditionsThirtyTwoBytes.RiceParameter
		delta256.entriesCount = add.AdditionsThirtyTwoBytes.EntriesCount
		delta256.firValFirPar = add.AdditionsThirtyTwoBytes.FirstValueFirstPart
		delta256.firValSecPar = add.AdditionsThirtyTwoBytes.FirstValueSecondPart
		delta256.firValThirPar = add.AdditionsThirtyTwoBytes.FirstValueThirdPart
		delta256.firValFourPar = add.AdditionsThirtyTwoBytes.FirstValueFourthPart
		var err error
		delta256.decodedData, err = decodeRiceIntegers256(delta256, logger)
		if err != nil {
			var errRiceDelta riceDelta
			return errRiceDelta, err
		}
	default:
		err := errors.New("unsupported or unimplemented encoded hashlist length!")
		logger.Error().Err(err).Msg("")
		var errRiceDelta riceDelta
		return errRiceDelta, err
	}
	
	riceDelta := riceDelta{
		delta32: delta32,
		delta256: delta256, 
	}

	return riceDelta, nil
}


func decodeRiceRemovals(hashlist *safebrowsing.HashList, logger *zerolog.Logger) (riceDelta32, error) {

	var delta32 riceDelta32

	if hashlist.CompressedRemovals != nil {
		delta32.encodedData = hashlist.CompressedRemovals.EncodedData
		delta32.kParam = hashlist.CompressedRemovals.RiceParameter
		delta32.entriesCount = hashlist.CompressedRemovals.EntriesCount
		delta32.firstValue = hashlist.CompressedRemovals.FirstValue
		var err error
		delta32.decodedData, err = decodeRiceIntegers32(delta32, logger)
		if err != nil {
			var errRiceDelta riceDelta32
			return errRiceDelta, err
		}
	} else {
		err := errors.New("CompressedRemovals in hashlist is nil!")
		logger.Error().Err(err).Msg("")
		return delta32, err
	}

	return delta32, nil
}
