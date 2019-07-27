package sshkey

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

const defBitSize = 4096

type Builder interface {
	BitSize(int) Builder
	KeyGen() Interface
}

type sshkeyBuilder struct {
	bitSize         int
	privateKeyBytes []byte
	publicKeyBytes  []byte
}

type sshkey struct {
	params sshkeyBuilder
}

type Interface interface {
	PublicKeyBytes() []byte
	PrivateKeyBytes() []byte
	PublicKeyStr() string
}

func New() *sshkeyBuilder {
	return &sshkeyBuilder{
		bitSize: defBitSize,
	}
}

func (s *sshkeyBuilder) BitSize(bitSize int) Builder {
	s.bitSize = bitSize
	return s
}

func (s *sshkeyBuilder) KeyGen() Interface {
	privateKey, err := generatePrivateKey(s.bitSize)
	if err != nil {
		log.Fatal(err.Error())
	}

	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	s.privateKeyBytes = privateKeyBytes
	s.publicKeyBytes = publicKeyBytes
	return &sshkey{
		params: *s,
	}
}

func (k *sshkey) PublicKeyBytes() []byte {
	return k.params.publicKeyBytes
}

func (k *sshkey) PrivateKeyBytes() []byte {
	return k.params.privateKeyBytes
}

func (k *sshkey) PublicKeyStr() string {
	return *(*string)(unsafe.Pointer(&k.params.publicKeyBytes))
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// generatePublicKey take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	return pubKeyBytes, nil
}
