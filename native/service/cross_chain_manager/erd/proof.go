package erd

import (
	"encoding/hex"

	"github.com/ElrondNetwork/elrond-go-core/hashing"
	"github.com/ElrondNetwork/elrond-go-core/hashing/blake2b"
	"github.com/ElrondNetwork/elrond-go-core/marshal"
	"github.com/ElrondNetwork/elrond-go/trie"
)

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

// NewErdProof provides an instance for erdProof
func NewErdProof(
	dataTrieProof [][]byte,
	dataTrieRootHash []byte,
	mainTrieProof [][]byte,
	mainTrieRootHash []byte,
	key []byte,
	address []byte,
) (*erdProof, error) {
	var err error
	dataTrieProof = decodeProof(dataTrieProof)
	dataTrieRootHash, err = hex.DecodeString(string(dataTrieRootHash))
	if err != nil || dataTrieRootHash == nil {
		return nil, ErrInvalidParameters
	}

	mainTrieProof = decodeProof(mainTrieProof)
	mainTrieRootHash, err = hex.DecodeString(string(mainTrieRootHash))
	if err != nil || mainTrieProof == nil {
		return nil, ErrInvalidParameters
	}

	key, err = hex.DecodeString(string(key))
	if err != nil {
		return nil, ErrInvalidParameters
	}
	address = decodeAddress(address)
	if address == nil {
		return nil, ErrInvalidParameters
	}

	return &erdProof{
		dataTrieRootHash: dataTrieRootHash,
		dataTrieProof:    dataTrieProof,
		mainTrieProof:    mainTrieProof,
		mainTrieRootHash: mainTrieRootHash,
		key:              key,
		address:          address,
	}, nil
}

// Verify verifies the given Merkle proof for both dataTrie and mainTrie
func (proof *erdProof) Verify() (bool, error) {
	marsh, hash := getMarshalizerAndHasher()

	verifier, err := trie.NewMerkleProofVerifier(marsh, hash)
	if err != nil {
		return false, err
	}

	isKeyInDataTrie, err := verifier.VerifyProof(proof.dataTrieRootHash, proof.key, proof.dataTrieProof)
	if err != nil || !isKeyInDataTrie {
		return false, err
	}

	isKeyInMainTrie, err := verifier.VerifyProof(proof.mainTrieRootHash, proof.address, proof.mainTrieProof)
	if err != nil || !isKeyInMainTrie {
		return false, err
	}

	return true, nil
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

func getMarshalizerAndHasher() (marshal.Marshalizer, hashing.Hasher) {
	marsh := &marshal.GogoProtoMarshalizer{}
	hash := blake2b.NewBlake2b()
	return marsh, hash
}
