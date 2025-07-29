package util

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"strings"
)

// DecryptAESCBC decrypts AES CBC encrypted data with UTF-8 key and IV
func DecryptAESCBC(encryptedData, key, iv string) (string, error) {
	// Decode base64 ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %v", err)
	}

	// Convert UTF-8 key and IV to bytes
	keyBytes := []byte(key)
	ivBytes := []byte(iv)

	// Validate key length (AES-256 requires 32 bytes)
	if len(keyBytes) != 32 {
		return "", fmt.Errorf("invalid key length: expected 32 bytes for AES-256, got %d", len(keyBytes))
	}

	// Validate IV length (AES requires 16 bytes)
	if len(ivBytes) != 16 {
		return "", fmt.Errorf("invalid IV length: expected 16 bytes, got %d", len(ivBytes))
	}

	// Create cipher block
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	// Create CBC mode
	mode := cipher.NewCBCDecrypter(block, ivBytes)

	// Decrypt
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	// Remove PKCS7 padding
	padding := int(decrypted[len(decrypted)-1])
	if padding > len(decrypted) || padding == 0 {
		return "", fmt.Errorf("invalid padding")
	}

	return string(decrypted[:len(decrypted)-padding]), nil
}

// ProcessEncryptedUserAuth handles the encrypted user authentication
func ProcessEncryptedUserAuth(credentials, key, iv string) (username, passwordFirstPart string, err error) {
	// Decrypt the credentials
	decryptedCredentials, err := DecryptAESCBC(credentials, key, iv)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt credentials: %v", err)
	}

	// Split the decrypted credentials by '*'
	parts := strings.Split(decryptedCredentials, "*")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid encrypted payload format: expected 2 parts separated by '*', got %d", len(parts))
	}

	return parts[0], parts[1], nil
}
