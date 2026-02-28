package util

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"strings"
)

// ProcessEncryptedUserAuth handles the full decryption flow
func ProcessEncryptedUserAuth(fullPayload, keyStr string) (username, password string, err error) {
	const separator = "*"
	key := []byte(keyStr)

	// 1. Split the payload by the constant separator
	parts := strings.Split(fullPayload, separator)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid payload: expected 2 parts separated by '*', got %d", len(parts))
	}

	// 2. Decrypt the first part (Username)
	userBytes, err := decryptInternal(parts[0], key)
	if err != nil {
		return "", "", fmt.Errorf("username decryption failed: %v", err)
	}

	// 3. Decrypt the second part (Password)
	passBytes, err := decryptInternal(parts[1], key)
	if err != nil {
		return "", "", fmt.Errorf("password decryption failed: %v", err)
	}

	return string(userBytes), string(passBytes), nil
}

// Internal helper to handle IV extraction and CBC decryption
func decryptInternal(b64Data string, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return nil, err
	}

	if len(data) < 16 {
		return nil, fmt.Errorf("payload too short for IV")
	}

	iv := data[:16]
	ciphertext := data[16:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	return unpadPKCS7(decrypted)
}

func unpadPKCS7(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padding := int(data[len(data)-1])
	if padding < 1 || padding > 16 {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:len(data)-padding], nil
}
