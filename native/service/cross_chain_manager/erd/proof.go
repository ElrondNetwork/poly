package erd

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
