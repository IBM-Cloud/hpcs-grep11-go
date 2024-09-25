/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"reflect"

	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/util"
)

// Example_wrapUnWrap_AESKey_WithRSA wraps an AES key with a RSA public key and then unwraps it with the RSA private key
// Flow: connect, generate AES key, generate RSA key pair, wrap/unwrap AES key with RSA key pair
func Example_wrapUnwrap_AESKey_WithRSA() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Generate a AES key
	aesKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN:   128 / 8,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: true, // must be true to be wrapped
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(aesKeyTemplate),
	}

	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generate AES key error: %s", err))
	} else {
		fmt.Println("Generated AES key")
	}

	// Generate RSA key pair
	publicExponent := 65537
	keySize := 4096
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_ENCRYPT:         true,
		ep11.CKA_WRAP:            true, // to wrap a key
		ep11.CKA_MODULUS_BITS:    keySize,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
		ep11.CKA_DECRYPT:   true,
		ep11.CKA_UNWRAP:    true, // to unwrap a key
	}

	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated RSA PKCS key pair")

	wrapKeyRequest := &pb.WrapKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		KeK:  generateKeyPairResponse.PubKey,
		Key:  generateKeyResponse.Key,
	}

	// Wrap the AES key
	wrapKeyResponse, err := cryptoClient.WrapKey(context.Background(), wrapKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Wrap AES key error: %s", err))
	}

	fmt.Println("Wrapped AES key")

	aesUnwrapKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:     ep11.CKO_SECRET_KEY,
		ep11.CKA_KEY_TYPE:  ep11.CKK_AES,
		ep11.CKA_VALUE_LEN: 128 / 8,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	unwrapRequest := &pb.UnwrapKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		KeK:      generateKeyPairResponse.PrivKey,
		Wrapped:  wrapKeyResponse.Wrapped,
		Template: util.AttributeMap(aesUnwrapKeyTemplate),
	}

	// Unwrap the AES key
	unwrappedResponse, err := cryptoClient.UnwrapKey(context.Background(), unwrapRequest)
	if err != nil {
		panic(fmt.Errorf("Unwrap AES key error: %s", err))
	}

	if !bytes.Equal(generateKeyResponse.GetCheckSum()[:3], unwrappedResponse.GetCheckSum()[:3]) {
		panic(fmt.Errorf("Unwrap AES key has a different checksum than the original key"))
	} else {
		fmt.Println("Unwrapped AES key")
	}

	// Output:
	// Generated AES key
	// Generated RSA PKCS key pair
	// Wrapped AES key
	// Unwrapped AES key
}

// Example_wrapUnWrap_AttributeBoundKey wraps an AES key with a RSA public key and then unwraps it with
// the RSA private key. The original key's attributes are preserved using the CKA_IBM_ATTRBOUND key attribute.
// Flow: connect, generate generic symmetric key for MAC use, generate AES key,
// generate RSA key pair, wrap/unwrap AES key with RSA key pair
func Example_wrapUnwrap_AttributeBoundKey() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Create MAC Key
	keyLen := 256 // bits
	macKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_KEY_TYPE:      ep11.CKK_GENERIC_SECRET,
		ep11.CKA_CLASS:         ep11.CKO_SECRET_KEY,
		ep11.CKA_VALUE_LEN:     keyLen / 8,
		ep11.CKA_IBM_ATTRBOUND: true,
	}

	generateMacKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_GENERIC_SECRET_KEY_GEN},
		Template: util.AttributeMap(macKeyTemplate),
	}

	generateMacKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateMacKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}

	fmt.Println("Generated Generic MAC key")

	// Generate a AES key
	aesKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN:     256 / 8,
		ep11.CKA_ENCRYPT:       true,
		ep11.CKA_DECRYPT:       true,
		ep11.CKA_EXTRACTABLE:   true, // must be true to be wrapped
		ep11.CKA_IBM_ATTRBOUND: true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(aesKeyTemplate),
	}

	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generate AES key error: %s", err))
	} else {
		fmt.Println("Generated AES key")
	}

	// Generate RSA key pair
	publicExponent := 65537
	keySize := 4096
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_ENCRYPT:         true,
		ep11.CKA_WRAP:            true, // to wrap a key
		ep11.CKA_MODULUS_BITS:    keySize,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
		ep11.CKA_IBM_ATTRBOUND:   true,
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:       true,
		ep11.CKA_SENSITIVE:     true,
		ep11.CKA_DECRYPT:       true,
		ep11.CKA_UNWRAP:        true, // to unwrap a key
		ep11.CKA_IBM_ATTRBOUND: true,
	}

	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated RSA PKCS key pair")

	wrapKeyRequest := &pb.WrapKeyRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_IBM_ATTRIBUTEBOUND_WRAP},
		KeK:    generateKeyPairResponse.PubKey,
		Key:    generateKeyResponse.Key,
		MacKey: generateMacKeyResponse.Key,
	}

	// Wrap the AES key
	wrapKeyResponse, err := cryptoClient.WrapKey(context.Background(), wrapKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Wrap AES key error: %s", err))
	}

	fmt.Println("Wrapped AES key")

	aesUnwrapKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:     ep11.CKO_SECRET_KEY,
		ep11.CKA_KEY_TYPE:  ep11.CKK_AES,
		ep11.CKA_VALUE_LEN: 256 / 8,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	unwrapRequest := &pb.UnwrapKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_IBM_ATTRIBUTEBOUND_WRAP},
		KeK:      generateKeyPairResponse.PrivKey,
		MacKey:   generateMacKeyResponse.Key,
		Wrapped:  wrapKeyResponse.Wrapped,
		Template: util.AttributeMap(aesUnwrapKeyTemplate),
	}

	// Unwrap the AES key
	unwrappedResponse, err := cryptoClient.UnwrapKey(context.Background(), unwrapRequest)
	if err != nil {
		panic(fmt.Errorf("Unwrap AES key error: %s", err))
	}

	if !bytes.Equal(generateKeyResponse.GetCheckSum()[:3], unwrappedResponse.GetCheckSum()[:3]) {
		panic(fmt.Errorf("Unwrap AES key has a different checksum than the original key"))
	} else {
		fmt.Println("Unwrapped AES key")
	}

	// Output:
	// Generated Generic MAC key
	// Generated AES key
	// Generated RSA PKCS key pair
	// Wrapped AES key
	// Unwrapped AES key
}

// Example_importExport_AESKey imports a raw plain text AES key into EP11.
// The raw AES key is a string of hex digits which are converted into
// a Golang byte slice prior to being imported into EP11. The imported
// AES key is then exported to compare the key's bytes with the original
// raw AES key's bytes.
//
// Flow: connect, generate base AES key used for importing, encrypt raw AES key,
// EP11 unwrap raw AES key with base AES key, encrypt data with imported AES key,
// decrypt data with imported AES key
//
// In addition, this example exports the imported AES key and verifies that the
// exported AES key matches the original raw AES key that was imported.
// Flow to verify that AES keys match: wrap imported AES key using base AES key,
// decrypt imported AES key using base AES key, compare key contents
func Example_importExport_AESKey() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	keyLen := 256 // 256-bit AES key

	// First an EP11 key blob is needed to encrypt and import the raw AES key into EP11
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_WRAP:      true,
		ep11.CKA_UNWRAP:    true,
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

	fmt.Println("Generated AES key that is used for import")

	// Raw AES key in string format to be imported into EP11
	rawAESKeyString := "84eb31c184aee86791bf095045914adbcbe08823b40024f02977b46c15e84d64" // 32 byte (256-bit) AES key

	// Convert string-based AES key bytes into binary
	rawAESKeyBinary, err := hex.DecodeString(rawAESKeyString)
	if err != nil {
		panic(fmt.Errorf("Error decoding raw AES key string: %s", err))
	}

	// Obtain initialization vector for encrypt and unwrap operations
	iv, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	fmt.Println("Generated IV")

	encryptSingleRequest := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:   generateKeyResponse.Key,
		Plain: rawAESKeyBinary, // raw AES key in binary format
	}

	// The raw AES key is then encrypted/wrapped by the EP11 AES key
	encryptSingleResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptSingle error: %s", err))
	}

	fmt.Println("Encrypted/wrapped raw AES key")

	// Key attribute template for imported AES key
	importAESKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN:   keyLen / 8,
		ep11.CKA_WRAP:        true,
		ep11.CKA_UNWRAP:      true,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: true, // allow imported AES key to be wrapped
		ep11.CKA_KEY_TYPE:    ep11.CKK_AES,
		ep11.CKA_CLASS:       ep11.CKO_SECRET_KEY,
	}

	// NOTE: The initialization vector that was used for the EncryptSingle operation above must
	// also be used for the UnwrapKey request in order to retain the original raw AES key bytes
	unwrapKeyRequest := &pb.UnwrapKeyRequest{
		Wrapped:  encryptSingleResponse.Ciphered, // The encrypted raw AES key to be unwrapped (imported)
		KeK:      generateKeyResponse.Key,        // The AES key used to encrypt/wrap the raw AES key
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Template: util.AttributeMap(importAESKeyTemplate),
	}

	// The wrapped AES key is unwrapped (imported) and becomes an EP11 AES key
	unwrapKeyResponse, err := cryptoClient.UnwrapKey(context.Background(), unwrapKeyRequest)
	if err != nil {
		panic(fmt.Errorf("UnwrapKey error: %s", err))
	}

	fmt.Println("Successfully imported raw AES key into EP11")

	// The new AES key is now wrapped/encrypted by the remote HSM
	// Use the new AES key to encrypt and decrypt some data

	message := []byte("Some data to encrypt/decrypt using the new imported AES key")

	encryptSingleRequest = &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:   unwrapKeyResponse.Unwrapped, // using the new imported AES key to encrypt
		Plain: message,
	}

	// The raw AES key is then encrypted/wrapped by the EP11 AES key
	encryptSingleResponse, err = cryptoClient.EncryptSingle(context.Background(), encryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptSingle error: %s", err))
	}

	fmt.Println("Encrypted sample message using new imported AES key")

	decryptSingleRequest := &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:      unwrapKeyResponse.Unwrapped, // using the new imported AES key to decrypt
		Ciphered: encryptSingleResponse.Ciphered,
	}

	decryptSingleResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptSingle error: %s", err))
	}

	decryptedText := decryptSingleResponse.Plain

	if !reflect.DeepEqual(message, decryptedText) {
		panic(fmt.Errorf("Failed comparing original plain text to decrypted data"))
	}

	fmt.Printf("Decrypted message\n%s\n", decryptedText)

	// Verify that imported key matches original raw AES key
	// Steps to export the imported AES key: wrap imported key with base AES key,
	// decrypt imported AES key with base AES key

	wrapKeyRequest := &pb.WrapKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:  unwrapKeyResponse.Unwrapped,
		KeK:  generateKeyResponse.Key,
	}

	wrapKeyResponse, err := cryptoClient.WrapKey(context.Background(), wrapKeyRequest)
	if err != nil {
		panic(fmt.Errorf("WrapKey error: %s", err))
	}

	fmt.Println("Wrapped imported AES key with base AES key")

	decryptSingleRequest = &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:      generateKeyResponse.Key, // using base AES key to decrypt the imported AES key
		Ciphered: wrapKeyResponse.Wrapped, // the wrapped imported AES key
	}

	decryptSingleResponse, err = cryptoClient.DecryptSingle(context.Background(), decryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptSingle error: %s", err))
	}

	fmt.Println("Decrypted imported AES key with base AES key")

	// Compare the contents of the imported AES key that was just
	// exported with the original raw AES key
	if !reflect.DeepEqual(rawAESKeyBinary, decryptSingleResponse.Plain) {
		panic(fmt.Errorf("Failed comparing original raw AES key with exported AES key"))
	}

	fmt.Println("The contents of the original raw AES key and the exported AES key match")

	// Output:
	// Generated AES key that is used for import
	// Generated IV
	// Encrypted/wrapped raw AES key
	// Successfully imported raw AES key into EP11
	// Encrypted sample message using new imported AES key
	// Decrypted message
	// Some data to encrypt/decrypt using the new imported AES key
	// Wrapped imported AES key with base AES key
	// Decrypted imported AES key with base AES key
	// The contents of the original raw AES key and the exported AES key match
}

// Example_export_RSAPrivKey exports a RSA private key created by the remote HSM.
// The exported key is used to encrypt and decrypt some sample text.
// NOTE: The exported PKCS#8 structure also contains the public key
//
// Flow: connect, generate RSA key pair, generate AES key (used to wrap and
// decrypt RSA private key), wrap RSA private key using AES key, decrypt RSA
// private key using AES key, parse the exported RSA private key PKCS#8
// structure into a Golang RSA key type, encrypt sample message, decrypt sample message,
// compare original message with decrypted message
//
// In addition, this example uses the original RSA private key to decrypt the
// sample message to ensure that the original sample message and the decrypted
// message (using the original RSA private key) are identical.
func Example_export_RSAPrivKey() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Generate RSA key pair.  The RSA private key is exported in this example.
	// NOTE: the RSA private key contains the RSA public key embedded within
	// the private key's ASN.1 structure
	publicExponent := 65537
	keySize := 4096
	// Setup public key template
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_ENCRYPT:         true,
		ep11.CKA_VERIFY:          true,
		ep11.CKA_MODULUS_BITS:    keySize,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
	}

	// Setup private key template
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:     true,
		ep11.CKA_SENSITIVE:   true,
		ep11.CKA_SIGN:        true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: true, // set this attribute to true since this private key is being wrapped below
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

	fmt.Println("Generated RSA key pair; the RSA private key is exported below")

	// Generate AES key that is used to wrap/export the RSA private key
	keyLen := 256 // 256-bit AES key

	// Setup the AES key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_WRAP:      true,
		ep11.CKA_UNWRAP:    true,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}

	fmt.Println("Generated AES key that is used to wrap/export RSA private key")

	// Obtain initialization vector for wrap and decrypt operations
	iv, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	fmt.Println("Generated IV")

	// Wrap the RSA private key with the AES key
	wrapKeyRequest := &pb.WrapKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:  generateKeyPairResponse.PrivKey,
		KeK:  generateKeyResponse.Key,
	}

	wrapKeyResponse, err := cryptoClient.WrapKey(context.Background(), wrapKeyRequest)
	if err != nil {
		panic(fmt.Errorf("WrapKey error: %s", err))
	}

	fmt.Println("Wrapped RSA private key with the AES key")

	// NOTE: The initialization vector that was used for the WrapKey operation above must
	// also be used for the DecryptSingle request in order to retain the RSA private key bytes
	decryptSingleRequest := &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:      generateKeyResponse.Key, // using the AES key to decrypt the wrapped RSA private key
		Ciphered: wrapKeyResponse.Wrapped, // the wrapped RSA private key
	}

	decryptSingleResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptSingle error: %s", err))
	}

	fmt.Println("Successfully decrypted RSA private key with AES key")

	// Parse the extracted RSA private key into a structure that Golang can use
	key, err := x509.ParsePKCS8PrivateKey(decryptSingleResponse.Plain)
	if err != nil {
		panic(fmt.Errorf("Parse RSA private key error: %s", err))
	}

	// Convert interface{} type returned from the previous step into *rsa.PrivateKey type
	extractedRSAPrivKey := key.(*rsa.PrivateKey)

	fmt.Println("Successfully parsed the exported PKCS#8 RSA private key")

	// Validate the RSA private key
	if err = extractedRSAPrivKey.Validate(); err != nil {
		panic(fmt.Errorf("Extracted RSA key is invalid: %s", err))
	}

	// Use the extracted RSA private key's PublicKey field to encrypt some plain text
	encryptedText, err := rsa.EncryptPKCS1v15(rand.Reader, &extractedRSAPrivKey.PublicKey, []byte("Carpe Diem"))
	if err != nil {
		panic(err)
	}

	fmt.Println("Encrypted text using the RSA public key embedded in the exported RSA private key")

	// Use the exported RSA private key to decrypt the ciphertext generated in the previous step
	decryptedText, err := extractedRSAPrivKey.Decrypt(rand.Reader, encryptedText, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("Decrypted text using the exported RSA private key")

	// Compare the original text "Carpe Diem" with the
	// decrypted text to ensure that they are identical
	if !reflect.DeepEqual("Carpe Diem", string(decryptedText)) {
		panic(fmt.Errorf("Decrypted text and 'Carpe Diem' are not identical"))
	}

	fmt.Println("The decrypted text matches the original message 'Carpe Diem'")

	// Decrypt the message using the original EP11 RSA private key
	decryptSingleRequest = &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		Key:      generateKeyPairResponse.PrivKey, // using the original RSA private key
		Ciphered: encryptedText,                   // the text encrypted by the exported RSA private key's public key field
	}

	decryptSingleResponse, err = cryptoClient.DecryptSingle(context.Background(), decryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptSingle error: %s", err))
	}

	fmt.Println("Decrypted text using the original RSA private key")

	// Compare the original text "Carpe Diem" with the
	// decrypted text to ensure that they are identical.
	// The original RSA private key was used to decrypt the text
	if !reflect.DeepEqual("Carpe Diem", string(decryptedText)) {
		panic(fmt.Errorf("Using the original RSA private key, the decrypted text and 'Carpe Diem' are not identical"))
	}

	fmt.Println("Using the original RSA private key, the decrypted text matches the original message 'Carpe Diem'")

	// Output:
	// Generated RSA key pair; the RSA private key is exported below
	// Generated AES key that is used to wrap/export RSA private key
	// Generated IV
	// Wrapped RSA private key with the AES key
	// Successfully decrypted RSA private key with AES key
	// Successfully parsed the exported PKCS#8 RSA private key
	// Encrypted text using the RSA public key embedded in the exported RSA private key
	// Decrypted text using the exported RSA private key
	// The decrypted text matches the original message 'Carpe Diem'
	// Decrypted text using the original RSA private key
	// Using the original RSA private key, the decrypted text matches the original message 'Carpe Diem'
}

// Example_export_ECPrivKey exports an EC private key (P256 Curve) created by the remote HSM.
// The exported key is used to perform sign and verify operations on some sample text.
// NOTE: The exported PKCS#8 structure also contains the public key
//
// Flow: connect, generate EC key pair, generate AES key (used to wrap and
// decrypt EC private key), wrap EC private key using AES key, decrypt EC
// private key using AES key, parse the exported EC private key PKCS#8
// structure into a Golang EC key type, sign sample message, verify signature
func Example_export_ECPrivKey() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	ecParameters, err := asn1.Marshal(util.OIDNamedCurveP256)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	publicKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_EC_PARAMS: ecParameters,
		ep11.CKA_VERIFY:    true, // allow public key to verify signatures
	}

	privateKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:        true, // allow private key to perform sign operations
		ep11.CKA_PRIVATE:     true,
		ep11.CKA_SENSITIVE:   true,
		ep11.CKA_EXTRACTABLE: true, // set this attribute to true since this private key is being wrapped below
	}

	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyECTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyECTemplate),
	}

	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated EC key pair; the EC private key is exported below")

	// Generate AES key that is used to wrap/export the EC private key
	keyLen := 256 // 256-bit AES key

	// Setup the AES key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_WRAP:      true,
		ep11.CKA_UNWRAP:    true,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}

	fmt.Println("Generated AES key that is used to wrap/export EC private key")

	// Obtain initialization vector for wrap and decrypt operations
	iv, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	fmt.Println("Generated IV")

	// Wrap the EC private key with the AES key
	wrapKeyRequest := &pb.WrapKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:  generateKeyPairResponse.PrivKey, // EC private key generated by the remote HSM
		KeK:  generateKeyResponse.Key,
	}

	wrapKeyResponse, err := cryptoClient.WrapKey(context.Background(), wrapKeyRequest)
	if err != nil {
		panic(fmt.Errorf("WrapKey error: %s", err))
	}

	fmt.Println("Wrapped EC private key with the AES key")

	// NOTE: The initialization vector that was used for the WrapKey operation above must
	// also be used for the DecryptSingle request in order to retain the EC private key bytes
	decryptSingleRequest := &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:      generateKeyResponse.Key, // using the AES key to decrypt the wrapped EC private key
		Ciphered: wrapKeyResponse.Wrapped, // the wrapped EC key
	}

	decryptSingleResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptSingle error: %s", err))
	}

	fmt.Println("Successfully decrypted EC private key with AES key")

	// Parse the extracted EC private key into a structure that Golang can use
	key, err := x509.ParsePKCS8PrivateKey(decryptSingleResponse.Plain)
	if err != nil {
		panic(fmt.Errorf("Parse EC private key error: %s", err))
	}

	// Convert interface{} type returned from the previous step into *ecdsa.PrivateKey type
	extractedECPrivKey := key.(*ecdsa.PrivateKey)

	fmt.Println("Successfully parsed the exported PKCS#8 EC private key")

	// Use the EC private key to sign some data
	signData := sha256.Sum256([]byte("This data needs to be signed"))

	signature, err := ecdsa.SignASN1(rand.Reader, extractedECPrivKey, signData[:])
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}

	fmt.Println("Signed data using the exported EC private key")

	// Verify the signature using the extracted EC private key's embedded public key field
	valid := ecdsa.VerifyASN1(&extractedECPrivKey.PublicKey, signData[:], signature)
	if !valid {
		fmt.Println("Signature was invalid")
	}

	fmt.Println("Verified signature using the exported EC private key's embedded public key field")

	// Output:
	// Generated EC key pair; the EC private key is exported below
	// Generated AES key that is used to wrap/export EC private key
	// Generated IV
	// Wrapped EC private key with the AES key
	// Successfully decrypted EC private key with AES key
	// Successfully parsed the exported PKCS#8 EC private key
	// Signed data using the exported EC private key
	// Verified signature using the exported EC private key's embedded public key field
}

// Example_import_RSA_Keypair imports a Golang generated RSA key pair into
// EP11 (transformed into EP11 key blobs).
//
// Flow: connect, generate AES key (used to encrypt and unwrap RSA key pair),
// generate RSA key pair using Golang standard library, marshal RSA private
// key into a PKCS#8 structure, marshal RSA public key into a standard public key
// ASN.1 structure, encrypt the Golang generated RSA private key PKCS#8 structure using
// the remote HSM, unwrap the encrypted RSA private key PKCS#8 structure using the
// remote HSM, unwrap the Golang generated RSA public key ASN.1 structure using the remote HSM
func Example_import_RSA_Keypair() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Generate an AES key using the remote HSM. The key is used to encrypt and import a RSA key pair.
	keyLen := 256 // 256-bit AES key

	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_WRAP:      true,
		ep11.CKA_UNWRAP:    true,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}

	fmt.Println("Generated AES key that is used for import")

	// Use Golang standard library to generate a RSA key pair
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(fmt.Errorf("Generate RSA Key Pair Error: %s", err))
	}

	// Marshal RSA private key into a PKCS#8 structure
	rsaPrivKeyBytes, err := x509.MarshalPKCS8PrivateKey(rsaPrivKey)
	if err != nil {
		panic(fmt.Errorf("Marshalling RSA private key error: %s", err))
	}

	// Save RSA public key
	rsaPubKey := &rsaPrivKey.PublicKey

	// Marshal RSA public key into a standard public key ASN.1 structure
	rsaPubKeyBytes, err := x509.MarshalPKIXPublicKey(rsaPubKey)
	if err != nil {
		panic(fmt.Errorf("Marshalling RSA public key error: %s", err))
	}

	// Obtain initialization vector for encrypt and unwrap operations
	iv, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	fmt.Println("Generated IV")

	encryptSingleRequest := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:   generateKeyResponse.Key,
		Plain: rsaPrivKeyBytes, // marshalled RSA private key
	}

	// Encrypt the marshalled RSA private key bytes using the AES key
	encryptSingleResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptSingle error: %s", err))
	}

	fmt.Println("Successfully encrypted the marshalled RSA private key")

	// Key attribute template for imported RSA private key
	importRSAPrivKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_UNWRAP:    true,
		ep11.CKA_DECRYPT:   true,
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
		ep11.CKA_KEY_TYPE:  ep11.CKK_RSA,
		ep11.CKA_CLASS:     ep11.CKO_PRIVATE_KEY,
	}

	// NOTE: The initialization vector that was used for the EncryptSingle operation above must
	// also be used for the UnwrapKey request in order to retain the original RSA private key bytes
	unwrapPrivKeyRequest := &pb.UnwrapKeyRequest{
		Wrapped:  encryptSingleResponse.Ciphered, // The encrypted RSA private key to be unwrapped (imported)
		KeK:      generateKeyResponse.Key,        // The AES key that was used to encrypt/wrap the RSA private key
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Template: util.AttributeMap(importRSAPrivKeyTemplate),
	}

	// The encrypted RSA private key is unwrapped (imported) and becomes an EP11 RSA private key
	unwrapPrivKeyResponse, err := cryptoClient.UnwrapKey(context.Background(), unwrapPrivKeyRequest)
	if err != nil {
		panic(fmt.Errorf("UnwrapKey error: %s", err))
	}

	_ = unwrapPrivKeyResponse.Unwrapped // simulate use of the imported private key

	fmt.Println("Successfully imported RSA private key into EP11")

	// Now import the marshalled RSA public key bytes into EP11
	// Key attribute template for imported RSA public key
	importRSAPubKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_WRAP:    true,
		ep11.CKA_ENCRYPT: true,
	}

	unwrapPubKeyRequest := &pb.UnwrapKeyRequest{
		Wrapped:  rsaPubKeyBytes,                                      // The marshalled RSA public key bytes to be unwrapped (imported)
		KeK:      generateKeyResponse.Key,                             // KeK is required for unwrap request, but is ignored when importing a public key
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_IBM_TRANSPORTKEY}, // Note the mechanism used to import public keys
		Template: util.AttributeMap(importRSAPubKeyTemplate),
	}

	// The RSA public key is unwrapped (imported) and becomes an EP11 RSA public key
	unwrapPubKeyResponse, err := cryptoClient.UnwrapKey(context.Background(), unwrapPubKeyRequest)
	if err != nil {
		panic(fmt.Errorf("UnwrapKey error: %s", err))
	}

	_ = unwrapPubKeyResponse.Unwrapped // simulate use of the imported public key

	fmt.Println("Successfully imported RSA public key into EP11")

	// Output:
	// Generated AES key that is used for import
	// Generated IV
	// Successfully encrypted the marshalled RSA private key
	// Successfully imported RSA private key into EP11
	// Successfully imported RSA public key into EP11
}

// Example_import_EC_Keypair imports a Golang generated EC key pair into
// EP11 (transformed into EP11 key blobs). The imported key pair is used
// to perform sign and verify operations on some sample data using the remote HSM.
//
// Flow: connect, generate AES key (used to encrypt and unwrap RSA key pair),
// generate EC key pair using Golang standard library, marshal EC private
// key into a PKCS#8 structure, marshal EC public key into a standard public key
// ASN.1 structure, encrypt the Golang generated EC private key PKCS#8 structure using
// the remote HSM, unwrap the encrypted EC private key PKCS#8 structure using the
// remote HSM, unwrap the Golang generated EC public key ASN.1 structure using the remote HSM,
// sign sample data using the imported EC private key, verify signature using imported EC public key
func Example_import_EC_Keypair() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Generate an AES key using the remote HSM. The key is used to encrypt and import an EC key pair.
	keyLen := 256 // 256-bit AES key

	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_WRAP:      true,
		ep11.CKA_UNWRAP:    true,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}

	fmt.Println("Generated AES key that is used for import")

	ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Errorf("Generate EC Key Pair Error: %s", err))
	}

	// Marshal EC private key into a PKCS#8 structure
	ecPrivKeyBytes, err := x509.MarshalPKCS8PrivateKey(ecPrivKey)
	if err != nil {
		panic(fmt.Errorf("Marshalling EC private key error: %s", err))
	}

	// Save EC public key
	ecPubKey := &ecPrivKey.PublicKey

	// Marshal EC public key into a standard public key ASN.1 structure
	ecPubKeyBytes, err := x509.MarshalPKIXPublicKey(ecPubKey)
	if err != nil {
		panic(fmt.Errorf("Marshalling EC public key error: %s", err))
	}

	// Obtain initialization vector for encrypt and unwrap operations
	iv, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	fmt.Println("Generated IV")

	encryptSingleRequest := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:   generateKeyResponse.Key,
		Plain: ecPrivKeyBytes, // marshalled EC private key
	}

	// Encrypt the marshalled EC private key bytes using the AES key
	encryptSingleResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptSingle error: %s", err))
	}

	fmt.Println("Successfully encrypted the marshalled EC private key")

	// Key attribute template for imported EC private key
	importECPrivKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:      true,
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
		ep11.CKA_KEY_TYPE:  ep11.CKK_EC,
		ep11.CKA_CLASS:     ep11.CKO_PRIVATE_KEY,
	}

	// NOTE: The initialization vector that was used for the EncryptSingle operation above must
	// also be used for the UnwrapKey request in order to retain the original EC private key bytes
	unwrapPrivKeyRequest := &pb.UnwrapKeyRequest{
		Wrapped:  encryptSingleResponse.Ciphered, // The encrypted EC private key to be unwrapped (imported)
		KeK:      generateKeyResponse.Key,        // The AES key that was used to encrypt/wrap the EC private key
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Template: util.AttributeMap(importECPrivKeyTemplate),
	}

	// The encrypted EC private key is unwrapped (imported) and becomes an EP11 EC private key
	unwrapPrivKeyResponse, err := cryptoClient.UnwrapKey(context.Background(), unwrapPrivKeyRequest)
	if err != nil {
		panic(fmt.Errorf("UnwrapKey error: %s", err))
	}

	fmt.Println("Successfully imported EC private key into EP11")

	// Now import the marshalled EC public key bytes into EP11
	// Key attribute template for imported EC public key
	importECPubKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VERIFY: true,
	}

	unwrapPubKeyRequest := &pb.UnwrapKeyRequest{
		Wrapped:  ecPubKeyBytes,                                       // The marshalled EC public key bytes to be unwrapped (imported)
		KeK:      generateKeyResponse.Key,                             // KeK is required for unwrap request, but is ignored when importing a public key
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_IBM_TRANSPORTKEY}, // Note the mechanism used to import public keys
		Template: util.AttributeMap(importECPubKeyTemplate),
	}

	// The EC public key is unwrapped (imported) and becomes an EP11 EC public key
	unwrapPubKeyResponse, err := cryptoClient.UnwrapKey(context.Background(), unwrapPubKeyRequest)
	if err != nil {
		panic(fmt.Errorf("UnwrapKey error: %s", err))
	}

	fmt.Println("Successfully imported EC public key into EP11")

	// The imported EC key pair is used to peform sign and verify operations on some sample data
	signData := []byte("This data needs to be signed")

	signSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: unwrapPrivKeyResponse.Unwrapped, // the imported EC private key
		Data:    signData,
	}

	// Sign the data using the imported EC private key
	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	fmt.Println("Data signed using imported EC private key")

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey:    unwrapPubKeyResponse.Unwrapped, // the imported EC public key
		Data:      signData,
		Signature: signSingleResponse.Signature,
	}

	// Verify the data
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("VerifySingle error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Data verified using imported EC public key")

	// Output:
	// Generated AES key that is used for import
	// Generated IV
	// Successfully encrypted the marshalled EC private key
	// Successfully imported EC private key into EP11
	// Successfully imported EC public key into EP11
	// Data signed using imported EC private key
	// Data verified using imported EC public key
}
