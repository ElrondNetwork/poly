package erd

import (
	"github.com/ElrondNetwork/elrond-go-core/hashing/blake2b"
	"github.com/ElrondNetwork/elrond-go-core/marshal"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewProof(t *testing.T) {
	marsh := &marshal.GogoProtoMarshalizer{}
	hash := blake2b.NewBlake2b()
	dataTrieRootHash, dataTrieProof, mainTrieRootHash, mainTrieProof, key, address := getMockData()

	proof, err := NewErdProof(dataTrieProof, dataTrieRootHash, mainTrieProof, mainTrieRootHash, key, address, marsh, hash)

	assert.Nil(t, err)
	assert.NotNil(t, proof)
}

func TestNewProof_WrongParams(t *testing.T) {
	marsh := &marshal.GogoProtoMarshalizer{}
	hash := blake2b.NewBlake2b()
	dataTrieRootHash, dataTrieProof, mainTrieRootHash, mainTrieProof, key, address := getMockData()
	mainTrieRootHash = []byte{1}

	proof, err := NewErdProof(dataTrieProof, dataTrieRootHash, mainTrieProof, mainTrieRootHash, key, address, marsh, hash)

	assert.Equal(t, ErrInvalidParameters, err)
	assert.Nil(t, proof)
}

func TestVerifyProof_Success(t *testing.T) {
	marsh := &marshal.GogoProtoMarshalizer{}
	hash := blake2b.NewBlake2b()
	dataTrieRootHash, dataTrieProof, mainTrieRootHash, mainTrieProof, key, address := getMockData()

	proof, err := NewErdProof(dataTrieProof, dataTrieRootHash, mainTrieProof, mainTrieRootHash, key, address, marsh, hash)
	assert.Nil(t, err)
	assert.NotNil(t, proof)

	ok, err := proof.Verify()
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyProof_Fail(t *testing.T) {
	marsh := &marshal.GogoProtoMarshalizer{}
	hash := blake2b.NewBlake2b()
	dataTrieRootHash, dataTrieProof, mainTrieRootHash, mainTrieProof, key, address := getMockData()
	mainTrieRootHash = dataTrieRootHash

	proof, err := NewErdProof(dataTrieProof, dataTrieRootHash, mainTrieProof, mainTrieRootHash, key, address, marsh, hash)
	assert.Nil(t, err)
	assert.NotNil(t, proof)

	ok, err := proof.Verify()
	assert.False(t, ok)
}

func getMockData() ([]byte, [][]byte, []byte, [][]byte, []byte, []byte) {
	dataTrieRootHash := []byte("66df366985cd68747dc9b0d0e84890a461aabc347bd779a276723a6dd2687e60")
	dataTrieProof := [][]byte{[]byte("0a070d06050703071012240b73756d000000000000000005004888d06daef6d4ce8a01d72812d08617b4b504a369e101")}

	mainTrieRootHash := []byte("64eb10fed64866d772eb76bfd6d8a96b4a31015326da8f8a4e78760ab1f400d3")
	mainTrieProof := [][]byte{
		[]byte("0a20344dba34a1ff7526c504ba908e7efdc008fa526d285880430d96a926ebeac4340a2099fe2e54856cd254d8f4101e6de04476f91b588f58d2d2d78ae082083772ef140a20ed82beacdd598ebf7dd422729fe4ec589ce9bbfdeb97d03860e802c5aa770ec00a20ffe7898bd511eebaf18d1239b20c1fd663bfcbc838de3302bdda1f6923e164d00a2088d02f82931e2e33c88217e3292b9dbf069f838834b154befe1cfa812255ac9d0a208fcf1c46e472d687b42bd0c30b655b3d630610369f263eaee24b67e0f83bfa850a20ff25ed342479df9b575b8ef2eefaffd58f40d60a81a877890ff938434a2a64510a20cc0e625872c6b7358d03a40af511bd02dbe7055d5195e765c507a5eb71cee3630a201bfa9daacfaa4a8634b47c680b0fbcf85e96662dea767201e5ab6882b5f52efb0a20e2db29e72f0311972539a2819b415b9b23d9b2080fb4fe772751bfe3f3ff0c230a20c823e6d5fa13efc0a5453b9cf877e426d4b1c1a2c73a5897044c9453cf7554260a20197f82cd564c146e0fec0bc36b0b9e0273cfeeb52a32dc0dcbd97180fcfc735a0a20662acec7d9383bb6fdca509a98fa16cdca8b4fb13a869a4919e88c43a532693d0a20b5ba2350795a9de5e9703222beda7348ce8bf78a0b1441e46a430ac41b2035ca0a20cf3fe16fc967eb83b2d09b9d1d20bfca9d97aa5ad2f44cbf4f9bb65d0659d5270a2053119a1154a1bff8330e7eface503205e604dfb901f8bc03c817fedc27b1aa540a0002"),
		[]byte("0a2067d37a8ce0624046aa6495ca90ea13c03dbed0526b5915e37c22283f52a0fa280a204c239d2f986ce4ebe096cd2b1fee5a0a5441cdd714a8ea739756627baf2543a80a20c3506992dd742e7ba809e8eb5b71377750bf3160d165fc0219bb0f3ee9f1547d0a209334b154e88b05d51121940749304f35ba491fa4f7c4ac163fe9badaadeb9e310a20245a4376422ff96919798254167b01c7cdb5111c611c5c309dd59f8e09caa7430a20acbdcddd337baedc1bdb94267aef701891ca1c3a6699b658d8bb23b37fa7def80a20a4b38b00547f8bfcccd6480336c5dc8eb44653312d5e8176919f57ef17da06120a202006a2ae1caa47b0855b77493a9f9f47ccdd98977c1bc11a6a20f72b3d1afe8d0a20c97a0719883773f37853673f48084dc640b36a24121f00e67bc265a13f4133fc0a205bc4a683a2ae4ebc74a5bf23477e3e56f7d33aaa125f07ac69567fb30e9d24d20a2066cab2cdd4d5eb7ac682aa97dad1f8876f4ed7ed4d25eedf9529124bb3d720a80a2084d1cfc7a75a0c5db499cb3dea34db0c8a4c8c501783a4da7080c6692083cdc20a2024a9a15f4d2a881d00ba3eefe1a6eb12d2b70b57646ff2bbc1dda3a37b78cc7f0a2087991421d869af7a444e5e968639c7e66f3ed97655c697505b5eb659c5ddf20d0a20b9940013ec0b0695ad58439f3aa6a17876a7f0ed22ea46cedc7f912b07bfd13e0a20d98078536adccfae9e1b1391599778fd8978f6cdc70d0cb1edf75aad2bee4f070a0002"),
		[]byte("0a20bb431c6dd1377ea2a0765c54040c1ed9953117d59e4a11959ad6a942fda246d70a000a000a000a000a000a000a000a000a20d52559fcc211059e07ee0cc5cbe13de0915930e3fd62089bfd522f6a87085a7f0a000a000a000a000a000a000a0002"),
		[]byte("0a01061220649c23d99499ebeb1ed739bb98f6ada470003908f4454e42dcd315abe536435900"),
		[]byte("0a2032fa6c0e240345d9d3359e9a51c4b844c9d11793cb6e6b79d9c4514605fda5780a000a000a200488c75b559af18860e121cc8a60a8be89e3057f30d192307c8e6eb8d6db05ed0a000a000a000a000a000a000a000a000a000a2058eddd01189dd48b27180356a102dd891981884decf5597a993ea0899bf0eada0a000a000a0002"),
		[]byte("0a3c0a0400050b040b07010608000d02010802070d01000a080e0c040d060f0e0a0d06000d08080804000005000000000000000000000000000000000010129901120200001a20d91ecdf21123fde80a3dfcc90e50b208896da7c6ea35e96983c2dab3b739498c222066df366985cd68747dc9b0d0e84890a461aabc347bd779a276723a6dd2687e602a20000000000000000005004888d06daef6d4ce8a01d72812d08617b4b504a369e1320700a5fe179643fe3a200139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e14a02010001"),
	}

	key := []byte("73756d")
	address := []byte("erd1qqqqqqqqqqqqqpgqfzydqmdw7m2vazsp6u5p95yxz76t2p9rd8ss0zp9ts")

	return dataTrieRootHash, dataTrieProof, mainTrieRootHash, mainTrieProof, key, address
}