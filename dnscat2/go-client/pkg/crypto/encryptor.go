// Package crypto implements the dnscat2 encryption layer.
package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/sha3"
)

const (
	HeaderLength    = 5
	SignatureLength = 6
)

// SASDict is the dictionary for Short Authentication String
var SASDict = []string{
	"THE", "DOG", "AND", "CAT", "RAN", "FAR", "FOR", "FUN",
	"HIS", "HER", "HIM", "SHE", "WAS", "HAD", "HAS", "ARE",
	"NOT", "ALL", "BUT", "CAN", "DID", "GOT", "GET", "HER",
	"ITS", "LET", "MAY", "NEW", "NOW", "OLD", "OUR", "OUT",
	"OWN", "SAY", "TOO", "TWO", "USE", "WAY", "WHO", "ANY",
	"BIG", "BOY", "DAY", "END", "FEW", "GOD", "GUY", "HOW",
	"JOB", "MAN", "MEN", "MRS", "ONE", "OWN", "PUT", "RED",
	"RUN", "SET", "SIT", "TEN", "TOP", "TRY", "WON", "YES",
	"YET", "ADD", "AGE", "AGO", "AID", "AIM", "AIR", "ARM",
	"ART", "ASK", "BAD", "BAR", "BED", "BIT", "BOX", "BUS",
	"BUY", "CAR", "CUT", "DUE", "EAR", "EAT", "EGG", "ERA",
	"EYE", "FAR", "FAT", "FIT", "FLY", "GAS", "GUN", "HIT",
	"HOT", "ICE", "ILL", "KEY", "KID", "LAW", "LAY", "LEG",
	"LIE", "LOT", "LOW", "MAP", "MIX", "NET", "NOR", "ODD",
	"OIL", "PAY", "PER", "POP", "RAW", "ROW", "SEA", "SEE",
	"SIR", "SIX", "SKY", "SON", "SUM", "SUN", "TAX", "TEA",
	"TIE", "WAR", "WAS", "WET", "WIN", "YEA", "ACE", "ACT",
	"ADS", "AFT", "ALE", "ANT", "APE", "ARC", "ARK", "AWE",
	"AXE", "BAG", "BAN", "BAT", "BAY", "BEE", "BET", "BIB",
	"BID", "BOG", "BOW", "BUD", "BUG", "BUN", "CAB", "CAM",
	"CAN", "CAP", "COB", "COD", "COG", "COT", "COW", "CRY",
	"CUB", "CUD", "CUP", "DAD", "DAM", "DEN", "DEW", "DIM",
	"DIP", "DOC", "DOE", "DOT", "DRY", "DUB", "DUD", "DUG",
	"DYE", "EEL", "ELF", "ELK", "ELM", "EMU", "EVE", "EWE",
	"FAN", "FAX", "FED", "FEE", "FEN", "FIG", "FIN", "FIR",
	"FIX", "FOB", "FOE", "FOG", "FOP", "FOX", "FRY", "FUN",
	"FUR", "GAB", "GAG", "GAL", "GAP", "GEL", "GEM", "GNU",
	"GOB", "GUM", "GUT", "GYM", "HAD", "HAM", "HAP", "HAT",
	"HEM", "HEN", "HEW", "HEX", "HID", "HIP", "HOB", "HOD",
	"HOE", "HOG", "HOP", "HUB", "HUE", "HUG", "HUM", "HUT",
	"INK", "INN", "ION", "IRE", "IRK", "IVY", "JAB", "JAG",
	"JAM", "JAR", "JAW", "JAY", "JET", "JIG", "JOB", "JOG",
}

// Encryptor handles encryption/decryption for dnscat2
type Encryptor struct {
	PresharedSecret string

	myPrivateKey   *ecdh.PrivateKey
	myPublicKey    []byte
	theirPublicKey []byte

	sharedSecret       [32]byte
	myAuthenticator    [32]byte
	theirAuthenticator [32]byte

	myWriteKey    [32]byte
	myMacKey      [32]byte
	theirWriteKey [32]byte
	theirMacKey   [32]byte

	nonce uint16
}

// NewEncryptor creates a new encryptor and generates a keypair
func NewEncryptor(presharedSecret string) (*Encryptor, error) {
	e := &Encryptor{
		PresharedSecret: presharedSecret,
	}

	// Generate ECDH keypair using P-256
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	e.myPrivateKey = privateKey
	e.myPublicKey = privateKey.PublicKey().Bytes()

	return e, nil
}

// GetMyPublicKey returns our public key (64 bytes for uncompressed P-256)
func (e *Encryptor) GetMyPublicKey() []byte {
	// P-256 public key in uncompressed form is 65 bytes (04 || X || Y)
	// dnscat2 uses 64 bytes (X || Y), so we strip the 0x04 prefix
	pubKey := e.myPublicKey
	if len(pubKey) == 65 && pubKey[0] == 0x04 {
		return pubKey[1:]
	}
	return pubKey
}

// SetTheirPublicKey sets their public key and derives all session keys
func (e *Encryptor) SetTheirPublicKey(theirPubKey []byte) error {
	// dnscat2 uses 64 bytes (X || Y), so we need to add 0x04 prefix
	var fullPubKey []byte
	if len(theirPubKey) == 64 {
		fullPubKey = append([]byte{0x04}, theirPubKey...)
	} else {
		fullPubKey = theirPubKey
	}

	curve := ecdh.P256()
	theirKey, err := curve.NewPublicKey(fullPubKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	shared, err := e.myPrivateKey.ECDH(theirKey)
	if err != nil {
		return fmt.Errorf("ECDH failed: %w", err)
	}

	e.theirPublicKey = theirPubKey
	copy(e.sharedSecret[:], shared[:32])

	// Derive keys
	e.makeKey("client_write_key", &e.myWriteKey)
	e.makeKey("client_mac_key", &e.myMacKey)
	e.makeKey("server_write_key", &e.theirWriteKey)
	e.makeKey("server_mac_key", &e.theirMacKey)

	// Generate authenticators if preshared secret is set
	if e.PresharedSecret != "" {
		e.makeAuthenticator("client", &e.myAuthenticator)
		e.makeAuthenticator("server", &e.theirAuthenticator)
	}

	return nil
}

// GetMyAuthenticator returns our authenticator
func (e *Encryptor) GetMyAuthenticator() []byte {
	return e.myAuthenticator[:]
}

// GetTheirAuthenticator returns their expected authenticator
func (e *Encryptor) GetTheirAuthenticator() []byte {
	return e.theirAuthenticator[:]
}

// makeKey derives a key using SHA3-256
func (e *Encryptor) makeKey(keyName string, result *[32]byte) {
	h := sha3.New256()
	h.Write(e.sharedSecret[:])
	h.Write([]byte(keyName))
	copy(result[:], h.Sum(nil))
}

// makeAuthenticator generates an authenticator
func (e *Encryptor) makeAuthenticator(authString string, buffer *[32]byte) {
	h := sha3.New256()
	h.Write([]byte(authString))
	h.Write(e.sharedSecret[:])
	h.Write(e.GetMyPublicKey())
	h.Write(e.theirPublicKey)
	h.Write([]byte(e.PresharedSecret))
	copy(buffer[:], h.Sum(nil))
}

// GetNonce returns the next nonce and increments
func (e *Encryptor) GetNonce() uint16 {
	n := e.nonce
	e.nonce++
	return n
}

// ShouldRenegotiate returns true if nonce is getting too high
func (e *Encryptor) ShouldRenegotiate() bool {
	return e.nonce > 0xFFF0
}

// CheckSignature validates the signature on incoming data
// Returns the data without the signature if valid
func (e *Encryptor) CheckSignature(data []byte) ([]byte, bool) {
	if len(data) < HeaderLength+SignatureLength {
		return nil, false
	}

	header := data[:HeaderLength]
	theirSig := data[HeaderLength : HeaderLength+SignatureLength]
	body := data[HeaderLength+SignatureLength:]

	// Calculate expected signature: H(mac_key || header || body)
	h := sha3.New256()
	h.Write(e.theirMacKey[:])
	h.Write(header)
	h.Write(body)
	goodSig := h.Sum(nil)

	// Compare truncated signature (first 6 bytes)
	if !bytes.Equal(theirSig, goodSig[:SignatureLength]) {
		return nil, false
	}

	// Return data without signature
	result := make([]byte, 0, len(header)+len(body))
	result = append(result, header...)
	result = append(result, body...)
	return result, true
}

// Decrypt decrypts the data (after signature is removed)
// Returns decrypted data and the nonce
func (e *Encryptor) Decrypt(data []byte) ([]byte, uint16, error) {
	if len(data) < HeaderLength+2 {
		return nil, 0, errors.New("data too short")
	}

	header := data[:HeaderLength]
	nonce := binary.BigEndian.Uint16(data[HeaderLength : HeaderLength+2])
	body := data[HeaderLength+2:]

	// Prepare nonce for Salsa20 (8 bytes)
	var nonceBytes [8]byte
	nonceBytes[6] = byte(nonce >> 8)
	nonceBytes[7] = byte(nonce)

	// Decrypt body
	decrypted := make([]byte, len(body))
	salsa20.XORKeyStream(decrypted, body, nonceBytes[:], &e.theirWriteKey)

	// Rebuild packet without nonce
	result := make([]byte, 0, len(header)+len(decrypted))
	result = append(result, header...)
	result = append(result, decrypted...)

	return result, nonce, nil
}

// Sign adds a signature to the packet
func (e *Encryptor) Sign(data []byte) []byte {
	if len(data) < HeaderLength {
		return data
	}

	header := data[:HeaderLength]
	body := data[HeaderLength:]

	// Calculate signature: H(mac_key || header || body)
	h := sha3.New256()
	h.Write(e.myMacKey[:])
	h.Write(header)
	h.Write(body)
	sig := h.Sum(nil)

	// Build: header + truncated_sig + body
	result := make([]byte, 0, len(header)+SignatureLength+len(body))
	result = append(result, header...)
	result = append(result, sig[:SignatureLength]...)
	result = append(result, body...)

	return result
}

// Encrypt encrypts the packet and adds the nonce
func (e *Encryptor) Encrypt(data []byte) []byte {
	if len(data) < HeaderLength {
		return data
	}

	header := data[:HeaderLength]
	body := data[HeaderLength:]

	nonce := e.GetNonce()

	// Prepare nonce for Salsa20 (8 bytes)
	var nonceBytes [8]byte
	nonceBytes[6] = byte(nonce >> 8)
	nonceBytes[7] = byte(nonce)

	// Encrypt body
	encrypted := make([]byte, len(body))
	salsa20.XORKeyStream(encrypted, body, nonceBytes[:], &e.myWriteKey)

	// Build: header + nonce + encrypted_body
	result := make([]byte, 0, len(header)+2+len(encrypted))
	result = append(result, header...)
	result = append(result, byte(nonce>>8), byte(nonce))
	result = append(result, encrypted...)

	return result
}

// PrintSAS prints the Short Authentication String
func (e *Encryptor) PrintSAS() string {
	h := sha3.New256()
	h.Write([]byte("authstring"))
	h.Write(e.sharedSecret[:])
	h.Write(e.GetMyPublicKey())
	h.Write(e.theirPublicKey)
	hash := h.Sum(nil)

	var words []string
	for i := 0; i < 6; i++ {
		idx := int(hash[i]) % len(SASDict)
		words = append(words, SASDict[idx])
	}

	return fmt.Sprintf("%s %s %s %s %s %s", words[0], words[1], words[2], words[3], words[4], words[5])
}

// Print prints encryptor debug info
func (e *Encryptor) Print() {
	fmt.Printf("my_public_key:    %x\n", e.GetMyPublicKey())
	fmt.Printf("their_public_key: %x\n", e.theirPublicKey)
	fmt.Printf("shared_secret:    %x\n", e.sharedSecret)
	if e.PresharedSecret != "" {
		fmt.Printf("my_authenticator:    %x\n", e.myAuthenticator)
		fmt.Printf("their_authenticator: %x\n", e.theirAuthenticator)
	}
	fmt.Printf("my_write_key:     %x\n", e.myWriteKey)
	fmt.Printf("my_mac_key:       %x\n", e.myMacKey)
	fmt.Printf("their_write_key:  %x\n", e.theirWriteKey)
	fmt.Printf("their_mac_key:    %x\n", e.theirMacKey)
}
