package utils

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// EncryptPrivateKey encrypts a private key with a password using DES-EDE3-CBC
func EncryptPrivateKey(key *rsa.PrivateKey, password string) ([]byte, error) {
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	keyBytes := DeriveKey(password, salt)
	block, err := des.NewTripleDESCipher(keyBytes[:24])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	keyData := x509.MarshalPKCS1PrivateKey(key)
	paddedData := PKCS7Pad(keyData, block.BlockSize())
	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, keyBytes[:8])
	mode.CryptBlocks(ciphertext, paddedData)
	blockType := "RSA PRIVATE KEY"
	headers := map[string]string{
		"Proc-Type": "4,ENCRYPTED",
		"DEK-Info":  fmt.Sprintf("DES-EDE3-CBC,%s", hex.EncodeToString(salt)),
	}
	pemBlock := &pem.Block{
		Type:    blockType,
		Headers: headers,
		Bytes:   ciphertext,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

// DeriveKey derives a 24-byte key from password and salt using OpenSSL's method
func DeriveKey(password string, salt []byte) []byte {
	key := make([]byte, 24)
	hash := md5.New()
	hash.Write([]byte(password))
	hash.Write(salt)
	copy(key[:16], hash.Sum(nil))
	hash.Reset()
	hash.Write(key[:16])
	hash.Write([]byte(password))
	hash.Write(salt)
	copy(key[16:], hash.Sum(nil)[:8])
	return key
}

// PKCS7Pad adds PKCS#7 padding to data
func PKCS7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// DecryptPrivateKey decrypts a private key with a password using DES-EDE3-CBC
func DecryptPrivateKey(block *pem.Block, password string) (interface{}, error) {
	if !x509.IsEncryptedPEMBlock(block) {
		return nil, fmt.Errorf("PEM block is not encrypted")
	}
	dekInfo := block.Headers["DEK-Info"]
	if dekInfo == "" {
		return nil, fmt.Errorf("missing DEK-Info header in encrypted private key")
	}
	parts := strings.Split(dekInfo, ",")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid DEK-Info format")
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid salt in DEK-Info: %w", err)
	}
	keyBytes := DeriveKey(password, salt)
	cipherBlock, err := des.NewTripleDESCipher(keyBytes[:24])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	plaintext := make([]byte, len(block.Bytes))
	mode := cipher.NewCBCDecrypter(cipherBlock, keyBytes[:8])
	mode.CryptBlocks(plaintext, block.Bytes)
	plaintext = PKCS7Unpad(plaintext)
	privateKey, err := x509.ParsePKCS1PrivateKey(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decrypted private key: %w", err)
	}
	return privateKey, nil
}

// PKCS7Unpad removes PKCS#7 padding from data
func PKCS7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding > len(data) {
		return data
	}
	return data[:len(data)-padding]
}

// CreatePKCS12Bundle creates a PKCS#12 bundle with the certificate and private key
func CreatePKCS12Bundle(keyPEM, certPEM []byte, password string) ([]byte, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}
	var privateKey interface{}
	var err error
	if x509.IsEncryptedPEMBlock(keyBlock) {
		privateKey, err = DecryptPrivateKey(keyBlock, password)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
	} else {
		// Try PKCS#8 first (for PQC keys), then fall back to PKCS#1
		privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			// Fall back to PKCS#1 for traditional RSA keys
			privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key (tried PKCS#8 and PKCS#1): %w", err)
			}
		}
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	p12Data, err := pkcs12.Encode(rand.Reader, privateKey, cert, nil, password)
	if err != nil {
		return nil, fmt.Errorf("failed to create PKCS#12 bundle: %w", err)
	}
	return p12Data, nil
}

// EncryptPEMBlock encrypts a PEM block with a password.
func EncryptPEMBlock(keyPEM []byte, password string) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt PEM block: %w", err)
	}

	return pem.EncodeToMemory(encryptedBlock), nil
} 