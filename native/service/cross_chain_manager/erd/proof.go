package erd

import "encoding/hex"

const (
	addressLen = 32
)

type erdProof struct {
	dataTrieProof    [][]byte
	dataTrieRootHash []byte
	mainTrieProof    [][]byte
	mainTrieRootHash []byte
	key              []byte
	address          []byte
}

func decodeProof(trieProofBytes [][]byte) [][]byte {
	proof := make([][]byte, 0)
	for _, hexProof := range trieProofBytes {
		bytesProof, err := hex.DecodeString(string(hexProof))
		if err != nil {
			return nil
		}

		proof = append(proof, bytesProof)
	}

	return proof
}

func decodeAddress(address []byte) []byte {
	bech32PubkeyConverter, err := NewBech32PubkeyConverter(addressLen)
	if err != nil {
		return nil
	}

	decodedAddress, err := bech32PubkeyConverter.Decode(string(address))
	if err != nil {
		return nil
	}

	return decodedAddress
}
