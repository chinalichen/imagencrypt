package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// DbKey is the AES key
var DbKey = "a_v3ry_10ng_key_"

// Encrypt aes-128 ECB mode
func Encrypt(src []byte) []byte {
	cb, err := aes.NewCipher([]byte(DbKey))
	if err != nil {
		return []byte{}
	}

	length := len(src)
	dist := make([]byte, length)

	if length < aes.BlockSize {
		copy(dist, src)
		return dist
	}

	i := 0
	for i = 0; i <= length-aes.BlockSize; i += aes.BlockSize {
		cb.Encrypt(dist[i:i+aes.BlockSize], src[i:i+aes.BlockSize])
	}
	copy(dist[i:], src[i:])

	return dist
}

// Decrypt aes-128 ECB mode
func Decrypt(src []byte) []byte {
	cb, err := aes.NewCipher([]byte(DbKey))
	if err != nil {
		return []byte{}
	}

	length := len(src)
	dist := make([]byte, length)

	if length < aes.BlockSize {
		copy(dist, src)
		return dist
	}

	i := 0
	for i = 0; i <= length-aes.BlockSize; i += aes.BlockSize {
		cb.Decrypt(dist[i:i+aes.BlockSize], src[i:i+aes.BlockSize])
	}
	copy(dist[i:], src[i:])

	return dist
}

// PCKS7Padding standard: PKCS #7
func PCKS7Padding(cipherText []byte, blockSize int) []byte {
	paddingValue := blockSize - len(cipherText)%blockSize
	padding := bytes.Repeat([]byte{byte(paddingValue)}, paddingValue)
	return append(cipherText, padding...)
}

// PCKS7Unpadding standard: PKCS #7
func PCKS7Unpadding(encryptedText []byte) []byte {
	length := len(encryptedText)
	paddingValue := int(encryptedText[length-1])
	return encryptedText[:length-paddingValue]
}

// NewEncrypt aes-128 CBC mode
func NewEncrypt(src []byte) []byte {
	block, err := aes.NewCipher([]byte(DbKey))
	if err != nil {
		return []byte{}
	}
	paddedSrc := PCKS7Padding(src, aes.BlockSize)
	cipherText := make([]byte, aes.BlockSize+len(paddedSrc))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return []byte{}
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], paddedSrc)
	return cipherText
}

// NewDecrypt aes-128 CBC mode
func NewDecrypt(src []byte) []byte {
	if len(src)%aes.BlockSize != 0 {
		return []byte{}
	}
	block, err := aes.NewCipher([]byte(DbKey))
	if err != nil {
		return []byte{}
	}
	iv := src[:aes.BlockSize]
	cipherText := src[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	dist := make([]byte, len(cipherText))
	mode.CryptBlocks(dist, cipherText)
	return PCKS7Unpadding(dist)
}

func NewSize(size int64) int64 {
	ivSize := int64(aes.BlockSize)
	paddingSize := aes.BlockSize - size%aes.BlockSize
	return ivSize + size + paddingSize
	// return (size/aes.BlockSize + 2) * aes.BlockSize
}
