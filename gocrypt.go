// Package 3dfosi/gocrypt provides simplified helper functions for using scrypt (128-bit salt, N=32768, r=8 and p=1) generated hash as a key to encrypt data with AES-256-GCM.
//
// Common use cases include but are not limited to encrypting data at rest for applications and symetric encryption automation prior to transfering files to destination.
package gocrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/scrypt"
)

// Function to generate a random salt
//
//   nByte in = Byte size of salt
func genSalt(nByte int) ([]byte, error) {
	b := make([]byte, nByte)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Function to create a hash with scrypt
//
//  salt []byte - Salt to create hash
//  pass string - Passphrase
func createHash(salt []byte, pass string) ([]byte, string, error) {

	if salt == nil {
		salt, _ = genSalt(16)
	}

	dk, err := scrypt.Key([]byte("some password"), salt, 32768, 8, 1, 32)
	if err != nil {
		log.Println("Scrypt Error:", err)
		return salt, string(dk), err
	}

	return salt, string(dk), nil

}

// Function to encrypt data
//
// Variables to pass in:
//
//   data []byte - Data to be encrypted
//   pass string - Passphrase to use for encryption
//
// Returns:
//
//   []byte - Encrypted Data
//   []byte - Salt
//   error  - Error
func Encrypt(data []byte, pass string) ([]byte, []byte, error) {

	salt, hash, err := createHash(nil, pass)
	if err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher([]byte(hash))
	if err != nil {
		log.Println("Encrypt - Block Error:", err)
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println("Encrypt - GCM Error:", err)
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return ciphertext, salt, nil
}

// Function to decrypt data
//
// Variables to pass in:
//
//   data []byte - Data to be encrypted
//   salt []byte - Salt to use to create hash
//   pass string - Passphrase to use for encryption
//
// Returns:
//
//   []byte - Decrypted Data
//   error  - Error
func Decrypt(data []byte, salt []byte, pass string) ([]byte, error) {

	_, hash, err := createHash([]byte(salt), pass)
	if err != nil {
		return nil, err
	}

	key := []byte(hash)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("Decrypt - Block Error:", err)
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println("Decrypt - GCM Error:", err)
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println("Decrypt - GCM Open Error:", err)
		return nil, err
	}

	return plaintext, nil

}

// Function to encrypt data and output to a file
//
// Variables to pass in:
//
//   file string - Name of the file (full path)
//   to   string - Specify destination path of file
//                 (must end with "/" ie. /opt/app/ instead of /opt/app)
//   pass string - Passphrase to use for encryption
//
// Returns:
//
//   []byte - Salt used to encrypt
//   error  - Error
func EncryptToFile(file string, to string, data []byte, passphrase string) ([]byte, error) {

	f, err := os.Create(file)
	if err != nil {
		log.Println("Encrypt to File - Create File Error:", err)
		return nil, err
	}

	defer f.Close()
	ciphertext, salt, err := Encrypt(data, passphrase)
	if err != nil {
		return nil, err
	}
	f.Write(ciphertext)

	return salt, nil

}

// Function to decrypt data from a file
//
// Variables to pass in:
//
//   file string - Name of the file (full path)
//   salt []byte - Salt used to create hash
//   pass string - Passphrase to use for encryption
//
// Returns:
//
//   []byte - Decrypted Data
//   error  - Error
func DecryptFromFile(file string, salt []byte, passphrase string) ([]byte, error) {

	data, err := ioutil.ReadFile(file)
	if err != nil {
		log.Println("Decrypt from File - Read File Error:", err)
	}

	decrypted, err := Decrypt(data, salt, passphrase)
	if err != nil {
		return nil, err
	}

	return decrypted, nil

}

// Function to encrypt an existing file.
//
// Variables to pass in:
//
//   file string - Name of the file
//   from string - Specify path of file
//   to   string - Specify destination path to output file
//                 (must end with "/" ie. /opt/app/ instead of /opt/app)
//   pass string - Passphrase to use for encryption
//
// Returns:
//
//   []byte - Salt used to encrypt
//   error  - Error
func EncryptFile(file string, from string, to string, passphrase string) error {

	data, err := ioutil.ReadFile(from + file)
	if err != nil {
		log.Println("Encrypt File - Read File Error:", err)
		return err
	}

	toFile := file
	if to != "" {
		toFile = to + file
		return err
	}

	xf, err := os.Create(toFile + ".3dfx")
	if err != nil {
		log.Println("Encrypt File - Create Encrypted File Error:", err)
		return err
	}

	defer xf.Close()
	cipherdata, salt, err := Encrypt(data, passphrase)
	if err != nil {
		return err
	}
	xf.Write(cipherdata)

	sf, err := os.Create(toFile + ".salt")
	if err != nil {
		log.Println("Encrypt File - Create Salt File Error:", err)
		return err
	}

	defer sf.Close()
	sf.Write(salt)

	return nil

}

// Function to decrypt data from  a file and output to a new file
//
// Variables to pass in:
//
//   file string - Name of the file
//   from string - Specify path of file
//   to   string - Specify destination path to output file
//                 (must end with "/" ie. /opt/app/ instead of /opt/app)
//   pass string - Passphrase to use for encryption
//
// Returns:
//
//   []byte - Salt used to encrypt
//   error  - Error
func DecryptFile(file string, from string, to string, passphrase string) error {

	data, err := ioutil.ReadFile(from + file + ".3dfx")
	if err != nil {
		log.Println("Encrypt File - Read File Error:", err)
	}

	salt, err := ioutil.ReadFile(from + file + ".salt")
	if err != nil {
		log.Println("Encrypt File - Read File Error:", err)
	}

	toFile := file
	if to != "" {
		toFile = to + file
	}

	xf, err := os.Create(toFile)
	if err != nil {
		log.Println("Encrypt File - Create Encrypted File Error:", err)
	}

	defer xf.Close()
	plaindata, err := Decrypt(data, salt, passphrase)
	if err != nil {
		return err
	}
	xf.Write(plaindata)

	return nil

}
