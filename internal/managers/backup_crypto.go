package managers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/pbkdf2"
)

// EncryptionMode determines how the encryption key is derived.
type EncryptionMode string

const (
	// EncryptModeDevice derives the key from Pi serial number + /cubeos/config/.keyfile salt.
	// Backups auto-decrypt on the same Pi. P0 Mode 1.
	EncryptModeDevice EncryptionMode = "device"

	// EncryptModePortable derives the key from a user-supplied passphrase via PBKDF2.
	// Backups can be decrypted on any device with the passphrase. P0 Mode 2.
	EncryptModePortable EncryptionMode = "portable"
)

const (
	// backupMagic is the file header identifying an encrypted CubeOS backup.
	backupMagic = "CUBEOS-BACKUP-V1"

	// magicLen is the length of the magic header.
	magicLen = 16

	// modeByte values
	modeByteDevice   byte = 0x01
	modeBytePortable byte = 0x02

	// cryptographic parameters
	saltLen       = 32
	nonceLen      = 12 // AES-GCM standard nonce size
	pbkdf2Iter    = 100000
	keyLen        = 32 // AES-256
	chunkSize     = 64 * 1024
	gcmOverhead   = 16 // GCM authentication tag
	keyfilePath   = "/cubeos/config/.keyfile"
	serialPathSys = "/sys/firmware/devicetree/base/serial-number"
)

// headerLen is: magic(16) + mode(1) + salt(32) + nonce(12) = 61 bytes
const headerLen = magicLen + 1 + saltLen + nonceLen

// EncryptBackup encrypts a backup archive using AES-256-GCM with streaming chunks.
//
// Mode "device": derives key from Pi serial + /cubeos/config/.keyfile salt.
// Mode "portable": derives key from passphrase via PBKDF2.
//
// File format: magic("CUBEOS-BACKUP-V1") + mode(1 byte) + salt(32 bytes) + nonce(12 bytes)
// followed by: [chunk_len(4 bytes) + encrypted_chunk]... + [0x00000000 terminator]
//
// Each chunk is independently encrypted with an incrementing nonce to support streaming.
func EncryptBackup(inputPath, outputPath string, mode EncryptionMode, passphrase string) error {
	if mode == EncryptModePortable && passphrase == "" {
		return errors.New("passphrase is required for portable encryption mode")
	}

	// Generate random salt
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate random base nonce
	baseNonce := make([]byte, nonceLen)
	if _, err := rand.Read(baseNonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Derive key
	key, err := deriveKey(mode, passphrase, salt)
	if err != nil {
		return fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Open input
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input: %w", err)
	}
	defer inFile.Close()

	// Create output
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output: %w", err)
	}
	defer outFile.Close()

	// Write header: magic + mode byte + salt + base nonce
	if _, err := outFile.Write([]byte(backupMagic)); err != nil {
		return err
	}
	modeByte := modeByteDevice
	if mode == EncryptModePortable {
		modeByte = modeBytePortable
	}
	if _, err := outFile.Write([]byte{modeByte}); err != nil {
		return err
	}
	if _, err := outFile.Write(salt); err != nil {
		return err
	}
	if _, err := outFile.Write(baseNonce); err != nil {
		return err
	}

	// Encrypt in chunks
	buf := make([]byte, chunkSize)
	chunkNonce := make([]byte, nonceLen)
	copy(chunkNonce, baseNonce)
	chunkIndex := uint32(0)
	lenBuf := make([]byte, 4)

	for {
		n, readErr := inFile.Read(buf)
		if n > 0 {
			// Increment nonce for each chunk
			incrementNonce(chunkNonce, chunkIndex)
			chunkIndex++

			// Encrypt chunk
			encrypted := gcm.Seal(nil, chunkNonce, buf[:n], nil)

			// Write: [encrypted_length(4 bytes)] [encrypted_data]
			binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))
			if _, err := outFile.Write(lenBuf); err != nil {
				return err
			}
			if _, err := outFile.Write(encrypted); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("failed to read input: %w", readErr)
		}
	}

	// Write terminator (zero-length chunk)
	binary.BigEndian.PutUint32(lenBuf, 0)
	if _, err := outFile.Write(lenBuf); err != nil {
		return err
	}

	log.Info().Str("mode", string(mode)).Str("output", outputPath).Msg("backup: encryption complete")
	return nil
}

// DecryptBackup decrypts a backup archive.
// Reads mode from header. If device mode: uses Pi serial + .keyfile.
// If portable mode: requires passphrase parameter.
func DecryptBackup(inputPath, outputPath string, passphrase string) error {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open encrypted backup: %w", err)
	}
	defer inFile.Close()

	// Read header
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(inFile, header); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Verify magic
	if string(header[:magicLen]) != backupMagic {
		return errors.New("not a CubeOS encrypted backup")
	}

	// Read mode
	var mode EncryptionMode
	switch header[magicLen] {
	case modeByteDevice:
		mode = EncryptModeDevice
	case modeBytePortable:
		mode = EncryptModePortable
	default:
		return fmt.Errorf("unknown encryption mode byte: 0x%02x", header[magicLen])
	}

	if mode == EncryptModePortable && passphrase == "" {
		return errors.New("passphrase is required for portable-encrypted backups")
	}

	// Extract salt and base nonce
	salt := header[magicLen+1 : magicLen+1+saltLen]
	baseNonce := header[magicLen+1+saltLen:]

	// Derive key
	key, err := deriveKey(mode, passphrase, salt)
	if err != nil {
		return fmt.Errorf("failed to derive decryption key: %w", err)
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create output
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output: %w", err)
	}
	defer outFile.Close()

	// Decrypt chunks
	chunkNonce := make([]byte, nonceLen)
	copy(chunkNonce, baseNonce)
	chunkIndex := uint32(0)
	lenBuf := make([]byte, 4)

	for {
		// Read chunk length
		if _, err := io.ReadFull(inFile, lenBuf); err != nil {
			return fmt.Errorf("failed to read chunk length: %w", err)
		}

		chunkLen := binary.BigEndian.Uint32(lenBuf)
		if chunkLen == 0 {
			break // terminator
		}

		// Sanity check: max chunk size is chunkSize + gcmOverhead
		if chunkLen > chunkSize+gcmOverhead {
			return fmt.Errorf("chunk too large: %d bytes", chunkLen)
		}

		// Read encrypted chunk
		encChunk := make([]byte, chunkLen)
		if _, err := io.ReadFull(inFile, encChunk); err != nil {
			return fmt.Errorf("failed to read chunk: %w", err)
		}

		// Decrypt
		incrementNonce(chunkNonce, chunkIndex)
		chunkIndex++

		plaintext, err := gcm.Open(nil, chunkNonce, encChunk, nil)
		if err != nil {
			return fmt.Errorf("decryption failed at chunk %d (wrong key or corrupted data): %w", chunkIndex-1, err)
		}

		if _, err := outFile.Write(plaintext); err != nil {
			return err
		}
	}

	log.Info().Str("mode", string(mode)).Str("output", outputPath).Msg("backup: decryption complete")
	return nil
}

// IsEncrypted checks if a file starts with the CubeOS backup encryption header.
func IsEncrypted(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer f.Close()

	magic := make([]byte, magicLen)
	n, err := f.Read(magic)
	if err != nil || n < magicLen {
		return false, nil
	}
	return string(magic) == backupMagic, nil
}

// GetEncryptionMode reads the mode byte from an encrypted backup header.
func GetEncryptionMode(filePath string) (EncryptionMode, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	header := make([]byte, magicLen+1)
	if _, err := io.ReadFull(f, header); err != nil {
		return "", fmt.Errorf("failed to read header: %w", err)
	}

	if string(header[:magicLen]) != backupMagic {
		return "", errors.New("not a CubeOS encrypted backup")
	}

	switch header[magicLen] {
	case modeByteDevice:
		return EncryptModeDevice, nil
	case modeBytePortable:
		return EncryptModePortable, nil
	default:
		return "", fmt.Errorf("unknown encryption mode byte: 0x%02x", header[magicLen])
	}
}

// EnsureKeyfile creates /cubeos/config/.keyfile if it doesn't exist.
// Called on first boot. Contains a random 32-byte salt used with Pi serial
// to derive device-specific encryption keys.
func EnsureKeyfile() error {
	if _, err := os.Stat(keyfilePath); err == nil {
		return nil // already exists
	}

	// Ensure directory exists
	if err := os.MkdirAll("/cubeos/config", 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate keyfile salt: %w", err)
	}

	if err := os.WriteFile(keyfilePath, salt, 0600); err != nil {
		return fmt.Errorf("failed to write keyfile: %w", err)
	}

	log.Info().Msg("backup: created device keyfile for encryption")
	return nil
}

// deriveKey derives the encryption key based on mode.
func deriveKey(mode EncryptionMode, passphrase string, salt []byte) ([]byte, error) {
	switch mode {
	case EncryptModeDevice:
		return getDeviceKey(salt)
	case EncryptModePortable:
		return pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iter, keyLen, sha256.New), nil
	default:
		return nil, fmt.Errorf("unknown encryption mode: %s", mode)
	}
}

// getDeviceKey derives the device-specific encryption key.
// Key = PBKDF2(SHA256, pi_serial_number, keyfile_salt ⊕ per-backup_salt, 100k, 32)
func getDeviceKey(backupSalt []byte) ([]byte, error) {
	serial, err := readPiSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to read Pi serial: %w", err)
	}

	keyfileSalt, err := os.ReadFile(keyfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyfile: %w", err)
	}

	// Combine keyfile salt with per-backup salt via XOR for key diversity
	combinedSalt := make([]byte, saltLen)
	for i := 0; i < saltLen; i++ {
		if i < len(keyfileSalt) {
			combinedSalt[i] = keyfileSalt[i] ^ backupSalt[i]
		} else {
			combinedSalt[i] = backupSalt[i]
		}
	}

	return pbkdf2.Key([]byte(serial), combinedSalt, pbkdf2Iter, keyLen, sha256.New), nil
}

// readPiSerial reads the Raspberry Pi serial number.
func readPiSerial() (string, error) {
	// Try /sys/firmware/devicetree/base/serial-number first (preferred)
	data, err := os.ReadFile(serialPathSys)
	if err == nil {
		serial := strings.TrimRight(string(data), "\x00\n")
		if serial != "" {
			return serial, nil
		}
	}

	// Fallback: parse /proc/cpuinfo
	cpuinfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", fmt.Errorf("cannot read serial: %w", err)
	}

	for _, line := range strings.Split(string(cpuinfo), "\n") {
		if strings.HasPrefix(line, "Serial") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	return "", errors.New("Pi serial number not found")
}

// incrementNonce sets the nonce for a given chunk index.
// Uses the base nonce with the last 4 bytes replaced by the chunk counter.
func incrementNonce(nonce []byte, index uint32) {
	binary.BigEndian.PutUint32(nonce[nonceLen-4:], index)
}
