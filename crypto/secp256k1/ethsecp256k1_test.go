package secp256k1_test

import (
	"encoding/hex"
	"testing"

	ethcrypto "github.com/maticnetwork/bor/crypto"
	gethsecp256k1 "github.com/maticnetwork/bor/crypto/secp256k1"
	"github.com/stretchr/testify/assert"

	tmcrypto "github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"
)

type keyData struct {
	priv            string
	pub             string
	decompressedPub string
	addr            string
}

var secpDataTable = []keyData{
	{
		priv: "e0a4dc43cebe4e4163dda6aec865548e2d54ede5d651a21978ce3c901d651f9d",
		pub:  "04403bdea50c7e1c1e0f806f4f7d8f6e50e693bc16ac678e1b5ce9001e585c075813b34a2b8f6a18ef24d324f11ec53db9f0cf8073b77345e42a1f9e0526507d0c",
		addr: "d9ebA42313c7F08B746ce1860EC326A205154f50",
	},
	{
		priv: "86052a190cfff18052e771b713243a07781bc20c5ed829339e633912e4ef84e2",
		pub:  "049d44ab1627fd1b5836e1365342b7f7063dad1e2f8c7ed9ac9fe065366fbf55f0dc64d67d128642aeceb9596f84a8045a34828f556f9884b979259b7b4efc020e",
		addr: "5B43bc10804Ab182c66ba4d441fdA5A49898cBa4",
	},
}

func TestPubKey(t *testing.T) {
	for _, d := range secpDataTable {
		privBytes, _ := hex.DecodeString(d.priv)
		pubBytes, _ := hex.DecodeString(d.pub)
		addrBytes, _ := hex.DecodeString(d.addr)

		var priv secp256k1.PrivKey = secp256k1.PrivKey(privBytes)
		pubKey := priv.PubKey()
		pub, _ := pubKey.(secp256k1.PubKey)

		// decompress pub key
		pubk, err := ethcrypto.DecompressPubkey(pub.Bytes())
		assert.NoError(t, err)

		// validate pubkey and address
		assert.Equal(t, ethcrypto.FromECDSAPub(pubk), secp256k1.PubKey(pubBytes).Bytes(), "Expected pub keys to match")
		assert.Equal(t, pubKey.Address().Bytes(), addrBytes, "Expected addresses to match")
	}
}

func TestPrivKey(t *testing.T) {
	// validate type and equality
	privKey, err := secp256k1.GenerateKey()
	assert.NoError(t, err)
	assert.True(t, privKey.Equals(privKey))
	assert.Implements(t, (*tmcrypto.PrivKey)(nil), privKey)

	// validate inequality
	privKey2, err := secp256k1.GenerateKey()
	assert.NoError(t, err)
	assert.False(t, privKey.Equals(privKey2))

	// validate Ethereum address equality
	addr := privKey.PubKey().Address()
	expectedAddr := ethcrypto.PubkeyToAddress(privKey.ToECDSA().PublicKey)
	assert.Equal(t, expectedAddr.Bytes(), addr.Bytes())

	// validate we can sign some bytes
	msg := []byte("hello world")
	sigHash := ethcrypto.Keccak256Hash(msg)
	expectedSig, err := gethsecp256k1.Sign(sigHash.Bytes(), privKey)
	assert.NoError(t, err)

	sig, err := privKey.Sign(msg)
	assert.NoError(t, err)
	assert.Equal(t, expectedSig, sig)
}
