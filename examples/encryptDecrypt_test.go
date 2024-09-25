/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"fmt"
	"reflect"

	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/util"
)

// This file contains examples of encrypt and decrypt operations for AES, DES3, and RSA keys.
// Three cipher flows are demonstrated for AES and DES3 keys:
// EP11 single-part (ESP), PKCS#11 single-part (PSP), and PKCS#11 multi-part (PMP)
//
// Two cipher flows are demonstrated for RSA keys: EP11 single-part (ESP) and PKCS#11 single-part (PSP).
// NOTE: RSA keys do not support PKCS#11 multi-part encrypt and decrypt operations
//
// Each test name has a suffix of ESP, PSP, or PMP denoting the cipher flow used in the test.
// Refer to the ciper flow diagram in README.md.

// Example_encryptDecrypt_AES_ESP generates an AES key then
// encrypts plain text and decrypts cipher text using the generated AES key
// Flow: connect, generate AES key, generate IV, encrypt EP11 single-part data, decrypt EP11 single-part data
// See "Cipher Flow 1" of the flow diagram in README.md
func Example_encryptDecrypt_AES_ESP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	keyLen := 256 // 256-bit AES key

	// Setup the AES key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	// When incorporating any key generation code in an application, the returned keyblob
	// should be saved (e.g. database) if the keyblob is required for future use
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated AES Key")

	// Obtain initialization vector for encrypt and decrypt operations
	iv, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	fmt.Println("Generated IV")

	plain := []byte("Hello, this is a very long and creative message")

	encryptSingleRequest := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:   generateKeyResponse.Key,
		Plain: plain,
	}

	encryptSingleResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptSingle error: %s", err))
	}

	ciphertext := encryptSingleResponse.Ciphered

	fmt.Println("Encrypted message")

	decryptSingleRequest := &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:      generateKeyResponse.Key,
		Ciphered: ciphertext,
	}

	decryptSingleResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptSingle error: %s", err))
	}

	plaintext := decryptSingleResponse.Plain

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing original plain text to decrypted data"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)

	// Output:
	// Generated AES Key
	// Generated IV
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message
}

// Example_encryptDecrypt_AES_PSP generates an AES key then
// encrypts plain text and decrypts cipher text using the generated AES key
// Flow: connect, generate AES key, generate IV, encrypt PKCS #11 single-part data, decrypt PKCS #11 single-part data
// See "Cipher Flow 2" of the flow diagram in README.md
func Example_encryptDecrypt_AES_PSP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	keyLen := 256 // 256-bit AES key

	// Setup the AES key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	// When incorporating any key generation code in an application, the returned keyblob
	// should be saved (e.g. database) if the keyblob is required for future use
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated AES Key")

	// Obtain initialization vector for encrypt and decrypt operations
	iv, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	fmt.Println("Generated IV")

	encryptInitRequest := &pb.EncryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:  generateKeyResponse.Key,
	}

	encryptInitResponse, err := cryptoClient.EncryptInit(context.Background(), encryptInitRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptInit error: %s", err))
	}

	plain := []byte("Hello, this is a very long and creative message")

	encryptRequest := &pb.EncryptRequest{
		State: encryptInitResponse.State,
		Plain: plain,
	}

	encryptResponse, err := cryptoClient.Encrypt(context.Background(), encryptRequest)
	if err != nil {
		panic(fmt.Errorf("Encrypt error: %s", err))
	}

	ciphertext := encryptResponse.Ciphered
	fmt.Println("Encrypted message")

	decryptInitRequest := &pb.DecryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:  generateKeyResponse.Key,
	}

	decryptInitResponse, err := cryptoClient.DecryptInit(context.Background(), decryptInitRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptInit error: %s", err))
	}

	decryptRequest := &pb.DecryptRequest{
		State:    decryptInitResponse.State,
		Ciphered: ciphertext,
	}

	decryptResponse, err := cryptoClient.Decrypt(context.Background(), decryptRequest)
	if err != nil {
		panic(fmt.Errorf("Decrypt error: %s", err))
	}

	plaintext := decryptResponse.Plain

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing original plain text to decrypted data"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)

	// Output:
	// Generated AES Key
	// Generated IV
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message
}

// Example_encryptDecrypt_AES_PMP generates an AES key then
// encrypts plain text and decrypts cipher text using the generated AES key
// Flow: connect, generate AES key, generate IV, encrypt PKCS #11 multi-part data, decrypt PKCS #11 multi-part data
// See "Cipher Flow 3" of the flow diagram in README.md
func Example_encryptDecrypt_AES_PMP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	keyLen := 256 // 256-bit AES key

	// Setup the AES key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	// When incorporating any key generation code in an application, the returned keyblob
	// should be saved (e.g. database) if the keyblob is required for future use
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated AES Key")

	// Obtain initialization vector for encrypt and decrypt operations
	iv, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	fmt.Println("Generated IV")

	encryptInitRequest := &pb.EncryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:  generateKeyResponse.Key,
	}

	encryptInitResponse, err := cryptoClient.EncryptInit(context.Background(), encryptInitRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptInit error: %s", err))
	}

	plain := []byte("Hello, this is a very long and creative message")

	// The data is encrypted in two update operations

	encryptUpdateRequest := &pb.EncryptUpdateRequest{
		State: encryptInitResponse.State,
		Plain: plain[:16],
	}

	encryptUpdateResponse, err := cryptoClient.EncryptUpdate(context.Background(), encryptUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptUpdate error: %s", err))
	}

	ciphertext := encryptUpdateResponse.Ciphered

	encryptUpdateRequest = &pb.EncryptUpdateRequest{
		State: encryptUpdateResponse.State,
		Plain: plain[16:],
	}

	encryptUpdateResponse, err = cryptoClient.EncryptUpdate(context.Background(), encryptUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptUpdate error: %s", err))
	}

	ciphertext = append(ciphertext, encryptUpdateResponse.Ciphered...)

	encryptFinalRequest := &pb.EncryptFinalRequest{
		State: encryptUpdateResponse.State,
	}

	encryptFinalResponse, err := cryptoClient.EncryptFinal(context.Background(), encryptFinalRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptFinal error: %s", err))
	}

	ciphertext = append(ciphertext, encryptFinalResponse.Ciphered...)
	fmt.Println("Encrypted message")

	decryptInitRequest := &pb.DecryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:  generateKeyResponse.Key,
	}

	decryptInitResponse, err := cryptoClient.DecryptInit(context.Background(), decryptInitRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptInit error: %s", err))
	}

	// The data is decrypted in two update operations

	decryptUpdateRequest := &pb.DecryptUpdateRequest{
		State:    decryptInitResponse.State,
		Ciphered: ciphertext[:16],
	}

	decryptUpdateResponse, err := cryptoClient.DecryptUpdate(context.Background(), decryptUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptUpdate error: %s", err))
	}

	plaintext := decryptUpdateResponse.Plain

	decryptUpdateRequest = &pb.DecryptUpdateRequest{
		State:    decryptUpdateResponse.State,
		Ciphered: ciphertext[16:],
	}

	decryptUpdateResponse, err = cryptoClient.DecryptUpdate(context.Background(), decryptUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptUpdate error: %s", err))
	}

	plaintext = append(plaintext, decryptUpdateResponse.Plain...)

	decryptFinalRequest := &pb.DecryptFinalRequest{
		State: decryptUpdateResponse.State,
	}

	decryptFinalResponse, err := cryptoClient.DecryptFinal(context.Background(), decryptFinalRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptFinal error: %s", err))
	}

	plaintext = append(plaintext, decryptFinalResponse.Plain...)

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing original plain text to decrypted data"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)

	// Output:
	// Generated AES Key
	// Generated IV
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message
}

// Example_encryptDecrypt_DES3_ESP generates a DES3 key then
// encrypts plain text and decrypts cipher text using the generated DES3 key
// Flow: connect, generate DES3 key, generate IV, encrypt EP11 single-part data, decrypt EP11 single-part data
// See "Cipher Flow 1" of the flow diagram in README.md
func Example_encryptDecrypt_DES3_ESP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	keyLen := 256 // 256-bit DES3 key

	// Setup the DES3 key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_DES3_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	// When incorporating any key generation code in an application, the returned keyblob
	// should be saved (e.g. database) if the keyblob is required for future use
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated DES3 Key")

	// Obtain initialization vector for encrypt and decrypt operations
	iv, err := util.GenerateIV(cryptoClient, util.DESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	fmt.Println("Generated IV")

	plain := []byte("Hello, this is a very long and creative message")

	encryptSingleRequest := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_DES3_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:   generateKeyResponse.Key,
		Plain: plain,
	}

	encryptSingleResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptSingle error: %s", err))
	}

	ciphertext := encryptSingleResponse.Ciphered

	fmt.Println("Encrypted message")

	decryptSingleRequest := &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_DES3_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:      generateKeyResponse.Key,
		Ciphered: ciphertext,
	}

	decryptSingleResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptSingle error: %s", err))
	}

	plaintext := decryptSingleResponse.Plain

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing original plain text to decrypted data"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)

	// Output:
	// Generated DES3 Key
	// Generated IV
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message
}

// Example_encryptDecrypt_DES3_PSP generates a DES3 key then
// encrypts plain text and decrypts cipher text using the generated DES3 key
// Flow: connect, generate DES3 key, generate IV, encrypt PKCS #11 single-part data, decrypt PKCS #11 single-part data
// See "Cipher Flow 2" of the flow diagram in README.md
func Example_encryptDecrypt_DES3_PSP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	keyLen := 256 // 256-bit DES3 key

	// Setup the DES3 key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_DES3_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	// When incorporating any key generation code in an application, the returned keyblob
	// should be saved (e.g. database) if the keyblob is required for future use
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated DES3 Key")

	// Obtain initialization vector for encrypt and decrypt operations
	iv, err := util.GenerateIV(cryptoClient, util.DESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	fmt.Println("Generated IV")

	encryptInitRequest := &pb.EncryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_DES3_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:  generateKeyResponse.Key,
	}

	encryptInitResponse, err := cryptoClient.EncryptInit(context.Background(), encryptInitRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptInit error: %s", err))
	}

	plain := []byte("Hello, this is a very long and creative message")

	encryptRequest := &pb.EncryptRequest{
		State: encryptInitResponse.State,
		Plain: plain,
	}

	encryptResponse, err := cryptoClient.Encrypt(context.Background(), encryptRequest)
	if err != nil {
		panic(fmt.Errorf("Encrypt error: %s", err))
	}

	ciphertext := encryptResponse.Ciphered
	fmt.Println("Encrypted message")

	decryptInitRequest := &pb.DecryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_DES3_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:  generateKeyResponse.Key,
	}

	decryptInitResponse, err := cryptoClient.DecryptInit(context.Background(), decryptInitRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptInit error: %s", err))
	}

	decryptRequest := &pb.DecryptRequest{
		State:    decryptInitResponse.State,
		Ciphered: ciphertext,
	}

	decryptResponse, err := cryptoClient.Decrypt(context.Background(), decryptRequest)
	if err != nil {
		panic(fmt.Errorf("Decrypt error: %s", err))
	}

	plaintext := decryptResponse.Plain

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing original plain text to decrypted data"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)

	// Output:
	// Generated DES3 Key
	// Generated IV
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message
}

// Example_encryptDecrypt_DES3_PMP generates a DES3 key then
// encrypts plain text and decrypts cipher text using the generated DES3 key
// Flow: connect, generate DES3 key, generate IV, encrypt PKCS #11 multi-part data, decrypt PKCS #11 multi-part data
// See "Cipher Flow 3" of the flow diagram in README.md
func Example_encryptDecrypt_DES3_PMP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	keyLen := 256 // 256-bit DES3 key

	// Setup the DES3 key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_DES3_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	// When incorporating any key generation code in an application, the returned keyblob
	// should be saved (e.g. database) if the keyblob is required for future use
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated DES3 Key")

	// Obtain initialization vector for encrypt and decrypt operations
	iv, err := util.GenerateIV(cryptoClient, util.DESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	fmt.Println("Generated IV")

	encryptInitRequest := &pb.EncryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_DES3_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:  generateKeyResponse.Key,
	}

	encryptInitResponse, err := cryptoClient.EncryptInit(context.Background(), encryptInitRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptInit error: %s", err))
	}

	plain := []byte("Hello, this is a very long and creative message")

	// The data is encrypted in two update operations

	encryptUpdateRequest := &pb.EncryptUpdateRequest{
		State: encryptInitResponse.State,
		Plain: plain[:16],
	}

	encryptUpdateResponse, err := cryptoClient.EncryptUpdate(context.Background(), encryptUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptUpdate error: %s", err))
	}

	ciphertext := encryptUpdateResponse.Ciphered

	encryptUpdateRequest = &pb.EncryptUpdateRequest{
		State: encryptUpdateResponse.State,
		Plain: plain[16:],
	}

	encryptUpdateResponse, err = cryptoClient.EncryptUpdate(context.Background(), encryptUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptUpdate error: %s", err))
	}

	ciphertext = append(ciphertext, encryptUpdateResponse.Ciphered...)
	encryptFinalRequest := &pb.EncryptFinalRequest{
		State: encryptUpdateResponse.State,
	}

	encryptFinalResponse, err := cryptoClient.EncryptFinal(context.Background(), encryptFinalRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptFinal error: %s", err))
	}

	ciphertext = append(ciphertext, encryptFinalResponse.Ciphered...)
	fmt.Println("Encrypted message")

	decryptInitRequest := &pb.DecryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_DES3_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:  generateKeyResponse.Key,
	}

	decryptInitResponse, err := cryptoClient.DecryptInit(context.Background(), decryptInitRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptInit error: %s", err))
	}

	// The data is decrypted in two update operations

	decryptUpdateRequest := &pb.DecryptUpdateRequest{
		State:    decryptInitResponse.State,
		Ciphered: ciphertext[:16],
	}

	decryptUpdateResponse, err := cryptoClient.DecryptUpdate(context.Background(), decryptUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptUpdate error: %s", err))
	}

	plaintext := decryptUpdateResponse.Plain

	decryptUpdateRequest = &pb.DecryptUpdateRequest{
		State:    decryptUpdateResponse.State,
		Ciphered: ciphertext[16:],
	}

	decryptUpdateResponse, err = cryptoClient.DecryptUpdate(context.Background(), decryptUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptUpdate error: %s", err))
	}

	plaintext = append(plaintext, decryptUpdateResponse.Plain...)

	decryptFinalRequest := &pb.DecryptFinalRequest{
		State: decryptUpdateResponse.State,
	}

	decryptFinalResponse, err := cryptoClient.DecryptFinal(context.Background(), decryptFinalRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptFinal error: %s", err))
	}

	plaintext = append(plaintext, decryptFinalResponse.Plain...)

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing original plain text to decrypted data"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)

	// Output:
	// Generated DES3 Key
	// Generated IV
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message
}

// Example_encryptDecrypt_RSA_OAEP_ESP generates a RSA key pair then encrypts plain text
// with the public key and decrypts cipher text with the private key.
// This uses the CKM_RSA_PKCS_OAEP mechanism to encrypt and decrypt data.
// Flow: connect, generate RSA key pair, encrypt EP11 single-part data, decrypt EP11 single-part data
// See "Cipher Flow 1" of the flow diagram in README.md
func Example_encryptDecrypt_RSA_OAEP_ESP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	publicExponent := 65537
	keySize := 4096
	// Setup public key template
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_ENCRYPT:         true,
		ep11.CKA_MODULUS_BITS:    keySize,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
	}

	// Setup private key template
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	// Generate RSA key pair
	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}
	fmt.Println("Generated RSA key pair")

	plain := []byte("Hello, this is a very long and creative message")

	// Valid combinations of mechanism parameter field values (must be the same for encrypt and decrypt):
	// MechParm HashMech: ep11.CKM_SHA_1         MechParm Mgf: pb.RSAOAEPParm_CkgMgf1Sha1 -- used in example below
	// MechParm HashMech: ep11.CKM_SHA224        MechParm Mgf: pb.RSAOAEPParm_CkgMgf1Sha224
	// MechParm HashMech: ep11.CKM_SHA256        MechParm Mgf: pb.RSAOAEPParm_CkgMgf1Sha256
	// MechParm HashMech: ep11.CKM_SHA384        MechParm Mgf: pb.RSAOAEPParm_CkgMgf1Sha384
	// MechParm HashMech: ep11.CKM_SHA512        MechParm Mgf: pb.RSAOAEPParm_CkgMgf1Sha512
	// MechParm HashMech: ep11.CKM_IBM_SHA3_224  MechParm Mgf: pb.RSAOAEPParm_CkgIbmMgf1Sha3_224
	// MechParm HashMech: ep11.CKM_IBM_SHA3_224  MechParm Mgf: pb.RSAOAEPParm_CkgIbmMgf1Sha3_224
	// MechParm HashMech: ep11.CKM_IBM_SHA3_256  MechParm Mgf: pb.RSAOAEPParm_CkgIbmMgf1Sha3_256
	// MechParm HashMech: ep11.CKM_IBM_SHA3_384  MechParm Mgf: pb.RSAOAEPParm_CkgIbmMgf1Sha3_384
	// MechParm HashMech: ep11.CKM_IBM_SHA3_512  MechParm Mgf: pb.RSAOAEPParm_CkgIbmMgf1Sha3_512

	// NOTE: Only the SHA1 HashMech and Mgf combination can be used on IBM Crypto Express CEX6 cards. All of
	// the HashMech and Mgf combinations work with IBM Crypto Express CEX7 and CEX8 cards.
	oaepMechParm := &pb.RSAOAEPParm{
		HashMech:         ep11.CKM_SHA_1,
		Mgf:              pb.RSAOAEPParm_CkgMgf1Sha1,
		EncodingParmType: pb.RSAOAEPParm_CkzNoDataSpecified,
	}

	encryptSingleRequest := &pb.EncryptSingleRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_RSA_PKCS_OAEP,
			Parameter: &pb.Mechanism_RSAOAEPParameter{RSAOAEPParameter: oaepMechParm},
		},
		Key:   generateKeyPairResponse.PubKey,
		Plain: plain,
	}

	encryptSingleResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptSingle error: %s", err))
	}

	ciphertext := encryptSingleResponse.Ciphered
	fmt.Println("Encrypted message")

	decryptSingleRequest := &pb.DecryptSingleRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_RSA_PKCS_OAEP,
			Parameter: &pb.Mechanism_RSAOAEPParameter{RSAOAEPParameter: oaepMechParm},
		},
		Key:      generateKeyPairResponse.PrivKey,
		Ciphered: ciphertext,
	}

	decryptSingleResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptSingle error: %s", err))
	}

	plaintext := decryptSingleResponse.Plain

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing original plain text to decrypted data"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)

	// Output:
	// Generated RSA key pair
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message
}

// Example_encryptDecrypt_RSA_ESP generates a RSA key pair then encrypts plain text
// with the public key and decrypts cipher text with the private key.
// This uses the CKM_RSA_PKCS mechanism to encrypt and decrypt data.
// Flow: connect, generate RSA key pair, encrypt EP11 single-part data, decrypt EP11 single-part data
// See "Cipher Flow 1" of the flow diagram in README.md
func Example_encryptDecrypt_RSA_ESP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	publicExponent := 65537
	keySize := 4096
	// Setup public key template
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_ENCRYPT:         true,
		ep11.CKA_MODULUS_BITS:    keySize,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
	}

	// Setup private key template
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	// Generate RSA key pair
	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}
	fmt.Println("Generated RSA key pair")

	plain := []byte("Hello, this is a very long and creative message")

	encryptSingleRequest := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		Key:   generateKeyPairResponse.PubKey,
		Plain: plain,
	}

	encryptSingleResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptSingle error: %s", err))
	}

	ciphertext := encryptSingleResponse.Ciphered
	fmt.Println("Encrypted message")

	decryptSingleRequest := &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		Key:      generateKeyPairResponse.PrivKey,
		Ciphered: ciphertext,
	}

	decryptSingleResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptSingle error: %s", err))
	}

	plaintext := decryptSingleResponse.Plain

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing original plain text to decrypted data"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)

	// Output:
	// Generated RSA key pair
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message
}

// Example_encryptDecrypt_RSA_OAEP_PSP generates a RSA key pair then encrypts plain text
// with the public key and decrypts cipher text with the private key.
// This uses the CKM_RSA_PKCS_OAEP mechanism to encrypt and decrypt data.
// Flow: connect, generate RSA key pair, encrypt PKCS#11 single-part data, decrypt PKCS#11 single-part data
// See "Cipher Flow 2" of the flow diagram in README.md
func Example_encryptDecrypt_RSA_OAEP_PSP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	publicExponent := 65537
	keySize := 4096
	// Setup public key template
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_ENCRYPT:         true,
		ep11.CKA_MODULUS_BITS:    keySize,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
	}

	// Setup private key template
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	// Generate RSA key pair
	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}
	fmt.Println("Generated RSA key pair")

	// Valid combinations of mechanism parameter field values (must be the same for encrypt and decrypt):
	// MechParm HashMech: ep11.CKM_SHA_1         MechParm Mgf: pb.RSAOAEPParm_CkgMgf1Sha1 -- used in example below
	// MechParm HashMech: ep11.CKM_SHA224        MechParm Mgf: pb.RSAOAEPParm_CkgMgf1Sha224
	// MechParm HashMech: ep11.CKM_SHA256        MechParm Mgf: pb.RSAOAEPParm_CkgMgf1Sha256
	// MechParm HashMech: ep11.CKM_SHA384        MechParm Mgf: pb.RSAOAEPParm_CkgMgf1Sha384
	// MechParm HashMech: ep11.CKM_SHA512        MechParm Mgf: pb.RSAOAEPParm_CkgMgf1Sha512
	// MechParm HashMech: ep11.CKM_IBM_SHA3_224  MechParm Mgf: pb.RSAOAEPParm_CkgIbmMgf1Sha3_224
	// MechParm HashMech: ep11.CKM_IBM_SHA3_224  MechParm Mgf: pb.RSAOAEPParm_CkgIbmMgf1Sha3_224
	// MechParm HashMech: ep11.CKM_IBM_SHA3_256  MechParm Mgf: pb.RSAOAEPParm_CkgIbmMgf1Sha3_256
	// MechParm HashMech: ep11.CKM_IBM_SHA3_384  MechParm Mgf: pb.RSAOAEPParm_CkgIbmMgf1Sha3_384
	// MechParm HashMech: ep11.CKM_IBM_SHA3_512  MechParm Mgf: pb.RSAOAEPParm_CkgIbmMgf1Sha3_512

	// NOTE: Only the SHA1 HashMech and Mgf combination can be used on IBM Crypto Express CEX6 cards. All of
	// the HashMech and Mgf combinations work with IBM Crypto Express CEX7 and CEX8 cards.
	oaepMechParm := &pb.RSAOAEPParm{
		HashMech:         ep11.CKM_SHA_1,
		Mgf:              pb.RSAOAEPParm_CkgMgf1Sha1,
		EncodingParmType: pb.RSAOAEPParm_CkzNoDataSpecified,
	}

	encryptInitRequest := &pb.EncryptInitRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_RSA_PKCS_OAEP,
			Parameter: &pb.Mechanism_RSAOAEPParameter{RSAOAEPParameter: oaepMechParm},
		},
		Key: generateKeyPairResponse.PubKey,
	}

	encryptInitResponse, err := cryptoClient.EncryptInit(context.Background(), encryptInitRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptInit error: %s", err))
	}

	plain := []byte("Hello, this is a very long and creative message")

	encryptRequest := &pb.EncryptRequest{
		State: encryptInitResponse.State,
		Plain: plain,
	}

	encryptResponse, err := cryptoClient.Encrypt(context.Background(), encryptRequest)
	if err != nil {
		panic(fmt.Errorf("Encrypt error: %s", err))
	}

	ciphertext := encryptResponse.Ciphered
	fmt.Println("Encrypted message")

	decryptInitRequest := &pb.DecryptInitRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_RSA_PKCS_OAEP,
			Parameter: &pb.Mechanism_RSAOAEPParameter{RSAOAEPParameter: oaepMechParm},
		},
		Key: generateKeyPairResponse.PrivKey,
	}

	decryptInitResponse, err := cryptoClient.DecryptInit(context.Background(), decryptInitRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptInit error: %s", err))
	}

	decryptRequest := &pb.DecryptRequest{
		State:    decryptInitResponse.State,
		Ciphered: ciphertext,
	}

	decryptResponse, err := cryptoClient.Decrypt(context.Background(), decryptRequest)
	if err != nil {
		panic(fmt.Errorf("Decrypt error: %s", err))
	}

	plaintext := decryptResponse.Plain

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing original plain text to decrypted data"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)

	// Output:
	// Generated RSA key pair
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message
}

// Example_encryptDecrypt_RSA_PSP generates a RSA key pair then encrypts plain text
// with the public key and decrypts cipher text with the private key.
// This uses the CKM_RSA_PKCS mechanism to encrypt and decrypt data.
// Flow: connect, generate RSA key pair, encrypt PKCS#11 single-part data, decrypt PKCS#11 single-part data
// See "Cipher Flow 2" of the flow diagram in README.md
func Example_encryptDecrypt_RSA_PSP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	publicExponent := 65537
	keySize := 4096
	// Setup public key template
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_ENCRYPT:         true,
		ep11.CKA_MODULUS_BITS:    keySize,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
	}

	// Setup private key template
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	// Generate RSA key pair
	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}
	fmt.Println("Generated RSA key pair")

	encryptInitRequest := &pb.EncryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		Key:  generateKeyPairResponse.PubKey,
	}

	encryptInitResponse, err := cryptoClient.EncryptInit(context.Background(), encryptInitRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptInit error: %s", err))
	}

	plain := []byte("Hello, this is a very long and creative message")

	encryptRequest := &pb.EncryptRequest{
		State: encryptInitResponse.State,
		Plain: plain,
	}

	encryptResponse, err := cryptoClient.Encrypt(context.Background(), encryptRequest)
	if err != nil {
		panic(fmt.Errorf("Encrypt error: %s", err))
	}

	ciphertext := encryptResponse.Ciphered
	fmt.Println("Encrypted message")

	decryptInitRequest := &pb.DecryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		Key:  generateKeyPairResponse.PrivKey,
	}

	decryptInitResponse, err := cryptoClient.DecryptInit(context.Background(), decryptInitRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptInit error: %s", err))
	}

	decryptRequest := &pb.DecryptRequest{
		State:    decryptInitResponse.State,
		Ciphered: ciphertext,
	}

	decryptResponse, err := cryptoClient.Decrypt(context.Background(), decryptRequest)
	if err != nil {
		panic(fmt.Errorf("Decrypt error: %s", err))
	}

	plaintext := decryptResponse.Plain

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing original plain text to decrypted data"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)

	// Output:
	// Generated RSA key pair
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message
}
