package secp256k1

import (
	"bytes"
	"crypto/ecdsa"

	ethcrypto "github.com/maticnetwork/bor/crypto"
	"github.com/maticnetwork/bor/crypto/secp256k1"

	tmcrypto "github.com/tendermint/tendermint/crypto"
	tmjson "github.com/tendermint/tendermint/libs/json"
)

const (
	// PrivKeySize defines the size of the PrivKey bytes
	PrivKeySize = 32
	// KeyType is the string constant for the EthSecp256k1 algorithm
	KeyType = "secp256k1"
	// SignatureSize is the size for sig data
	SignatureSize = 65
)

// Amino encoding names
const (
	// PrivKeyName defines the amino encoding name for the EthSecp256k1 private key
	PrivKeyName = "tendermint/PrivKeySecp256k1"
	// PubKeyName defines the amino encoding name for the EthSecp256k1 public key
	PubKeyName = "tendermint/PubKeySecp256k1"
)

func init() {
	tmjson.RegisterType(PubKey{}, PubKeyName)
	tmjson.RegisterType(PrivKey{}, PrivKeyName)
}

// ----------------------------------------------------------------------------
// secp256k1 Private Key

var _ tmcrypto.PrivKey = PrivKey{}

// PrivKey defines a type alias for an ecdsa.PrivateKey that implements
// Tendermint's PrivateKey interface.
type PrivKey []byte

// GenPrivKey generates a new random private key. It returns an error upon
// failure.
func GenPrivKey() PrivKey {
	priv, err := ethcrypto.GenerateKey()
	if err != nil {
		return PrivKey{}
	}

	return PrivKey(ethcrypto.FromECDSA(priv))
}

// PubKey returns the ECDSA private key's public key.
func (privKey PrivKey) PubKey() tmcrypto.PubKey {
	ecdsaPKey := privKey.ToECDSA()
	return PubKey(ethcrypto.CompressPubkey(&ecdsaPKey.PublicKey))
}

// Bytes returns the raw ECDSA private key bytes.
func (privKey PrivKey) Bytes() []byte {
	return []byte(privKey)
}

// Sign creates a recoverable ECDSA signature on the secp256k1 curve over the
// Keccak256 hash of the provided message. The produced signature is 65 bytes
// where the last byte contains the recovery ID.
func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	return ethcrypto.Sign(ethcrypto.Keccak256Hash(msg).Bytes(), privKey.ToECDSA())
}

// Equals returns true if two ECDSA private keys are equal and false otherwise.
func (privKey PrivKey) Equals(other tmcrypto.PrivKey) bool {
	if other, ok := other.(PrivKey); ok {
		return bytes.Equal(privKey.Bytes(), other.Bytes())
	}

	return false
}

// ToECDSA returns the ECDSA private key as a reference to ecdsa.PrivateKey type.
// The function will panic if the private key is invalid.
func (privKey PrivKey) ToECDSA() *ecdsa.PrivateKey {
	key, err := ethcrypto.ToECDSA(privKey)
	if err != nil {
		panic(err)
	}
	return key
}

// Type represents key type
func (privKey PrivKey) Type() string {
	return KeyType
}

// ----------------------------------------------------------------------------
// secp256k1 Public Key

var _ tmcrypto.PubKey = (*PubKey)(nil)

// PubKey defines a type alias for an ecdsa.PublicKey that implements Tendermint's PubKey
// interface. It represents the 33-byte compressed public key format.
type PubKey []byte

// PubKeySize is comprised of 32 bytes for one field element
// (the x-coordinate), plus one byte for the parity of the y-coordinate.
const PubKeySize = 33

// Address returns the address of the ECDSA public key.
// The function will panic if the public key is invalid.
func (key PubKey) Address() tmcrypto.Address {
	pubk, err := ethcrypto.DecompressPubkey(key)
	if err != nil {
		panic(err)
	}

	return tmcrypto.Address(ethcrypto.PubkeyToAddress(*pubk).Bytes())
}

// Bytes returns the raw bytes of the ECDSA public key.
// The function panics if the key cannot be marshaled to bytes.
func (key PubKey) Bytes() []byte {
	return []byte(key)
}

// VerifySignature verifies that the ECDSA public key created a given signature over
// the provided message. It will calculate the Keccak256 hash of the message
// prior to verification.
func (key PubKey) VerifySignature(msg []byte, sig []byte) bool {
	if len(sig) == 65 {
		// remove recovery ID if contained in the signature
		sig = sig[:len(sig)-1]
	}

	// the signature needs to be in [R || S] format when provided to VerifySignature
	return secp256k1.VerifySignature(key, ethcrypto.Keccak256Hash(msg).Bytes(), sig)
}

// Equals returns true if two ECDSA public keys are equal and false otherwise.
func (key PubKey) Equals(other tmcrypto.PubKey) bool {
	if other, ok := other.(PubKey); ok {
		return bytes.Equal(key.Bytes(), other.Bytes())
	}

	return false
}

// Type represents key type
func (key PubKey) Type() string {
	return KeyType
}
