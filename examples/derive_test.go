/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"bytes"
	"context"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/util"
)

// Example_deriveKey_DH derives keys and shares an encrypted message between two users
// Flow: connect, generate Diffie-Hellman key pairs, derive keys from Diffie-Hellman key pairs, share encypted message
func Example_deriveKey_DH() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	dhDomainTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIME_BITS: 2048,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_DH_PKCS_PARAMETER_GEN},
		Template: util.AttributeMap(dhDomainTemplate),
	}

	// Create Diffie-Hellman domain parameters for Alice and Bob to use. They are used by the Diffie-Hellman GenerateKeyPair requests.
	commonGenerateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey error: %s", err))
	}

	fmt.Println("Generated Diffie-Hellman domain parameters for Alice and Bob")

	commonPublicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_DERIVE:            true,
		ep11.CKA_EXTRACTABLE:       false,
		ep11.CKA_IBM_STRUCT_PARAMS: commonGenerateKeyResponse.KeyBytes,
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_DERIVE:      true,
		ep11.CKA_PRIVATE:     true,
		ep11.CKA_SENSITIVE:   true,
		ep11.CKA_EXTRACTABLE: false,
	}

	// Now generate the Diffie-Hellman key pair for Alice using Alice's domain parameters created in the previous step
	aliceGenerateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_DH_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(commonPublicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	aliceGenerateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), aliceGenerateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated Diffie-Hellman key pair for Alice")

	// Now generate the Diffie-Hellman key pair for Bob using Bob's domain parameters created in the previous step
	bobGenerateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_DH_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(commonPublicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	bobGenerateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), bobGenerateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated Diffie-Hellman key pair for Bob")

	deriveKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:     ep11.CKO_SECRET_KEY,
		ep11.CKA_KEY_TYPE:  ep11.CKK_AES,
		ep11.CKA_VALUE_LEN: 128 / 8,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	// The next step is to derive an AES key for Alice and Bob using each other's public key information
	// Get contents of public key
	alicePublicKey := util.DHPubKeyASN{}

	_, err = asn1.Unmarshal(aliceGenerateKeyPairResponse.PubKeyBytes, &alicePublicKey)
	if err != nil {
		panic(fmt.Errorf("Failed to unmarshal Alice's public key: %s", err))
	}

	bobPublicKey := util.DHPubKeyASN{}

	_, err = asn1.Unmarshal(bobGenerateKeyPairResponse.PubKeyBytes, &bobPublicKey)
	if err != nil {
		panic(fmt.Errorf("Failed to unmarshal Bob's public key: %s", err))
	}

	// Retrieve integer from public key: Alice's and Bob's public key is still ASN1 integer encoded, therefore, they need to be decoded
	var bigIntData *big.Int

	_, err = asn1.Unmarshal(bobPublicKey.PublicKey.Bytes, &bigIntData)
	if err != nil {
		panic(fmt.Errorf("Failed to unmarshal Bob's public key integer: %s", err))
	}

	bobPubInteger := bigIntData.Bytes()

	_, err = asn1.Unmarshal(alicePublicKey.PublicKey.Bytes, &bigIntData)
	if err != nil {
		panic(fmt.Errorf("Failed to unmarshal Alice's public key integer: %s", err))
	}

	alicePubInteger := bigIntData.Bytes()

	aliceDeriveKeyRequest := &pb.DeriveKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_DH_PKCS_DERIVE, Parameter: util.SetMechParm(bobPubInteger)},
		Template: util.AttributeMap(deriveKeyTemplate),
		BaseKey:  aliceGenerateKeyPairResponse.PrivKey,
	}

	aliceDeriveKeyResponse, err := cryptoClient.DeriveKey(context.Background(), aliceDeriveKeyRequest)
	if err != nil {
		panic(fmt.Errorf("DeriveKey error: %s", err))
	}

	fmt.Println("Key derived for Alice")

	bobDeriveKeyRequest := &pb.DeriveKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_DH_PKCS_DERIVE, Parameter: util.SetMechParm(alicePubInteger)},
		Template: util.AttributeMap(deriveKeyTemplate),
		BaseKey:  bobGenerateKeyPairResponse.PrivKey,
	}

	bobDeriveKeyResponse, err := cryptoClient.DeriveKey(context.Background(), bobDeriveKeyRequest)
	if err != nil {
		panic(fmt.Errorf("DeriveKey error: %s", err))
	}

	fmt.Println("Key derived for Bob")

	// Encrypt with Alice's key and decrypt with Bob's key
	var msg = []byte("hello world!")

	// Obtain initialization vector for encrypt and decrypt operations
	iv, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	encryptRequest := &pb.EncryptSingleRequest{
		Key:   aliceDeriveKeyResponse.NewKey,
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Plain: msg,
	}

	encryptResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptSingle error: %s", err))
	}

	decryptRequest := &pb.DecryptSingleRequest{
		Key:      bobDeriveKeyResponse.NewKey,
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Ciphered: encryptResponse.Ciphered,
	}

	decryptResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptSingle error: %s", err))
	}

	if !bytes.Equal(decryptResponse.Plain, msg) {
		panic(fmt.Errorf("Decrypted message[%v] is different from the original message: [%v]", decryptResponse.Plain, msg))
	} else {
		fmt.Println("Alice and Bob generated the same derived key")
	}

	// Output:
	// Generated Diffie-Hellman domain parameters for Alice and Bob
	// Generated Diffie-Hellman key pair for Alice
	// Generated Diffie-Hellman key pair for Bob
	// Key derived for Alice
	// Key derived for Bob
	// Alice and Bob generated the same derived key
}

// Example_deriveKey_EC generates EC key pairs for Alice and Bob and then derives AES keys for both
// of them using the Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) key agreement protocol.
// The names Bob and Alice are described in https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange.
//
// Flow: connect, generate key EC pairs for Alice and Bob, derive AES key for Bob, derive AES key for Alice,
// encrypt with Alice's AES key and decrypt with Bob's AES key
func Example_deriveKey_EC() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Generate EC key pairs for Alice and Bob
	ecParameters, err := asn1.Marshal(util.OIDNamedCurveP256)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_EC_PARAMS:   ecParameters,
		ep11.CKA_EXTRACTABLE: false,
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_DERIVE:      true,
		ep11.CKA_EXTRACTABLE: false,
	}

	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	// Generate Alice's EC key pair
	aliceECKeypairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("Generate Alice EC key pair error: %s", err))
	}

	fmt.Println("Generated Alice EC key pair")

	// Generate Bob's EC key pair
	bobECKeypairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("Generate Bob EC key pair error: %s", err))
	}

	fmt.Println("Generated Bob EC key pair")

	// Derive AES key for Alice and Bob
	deriveKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:     ep11.CKO_SECRET_KEY,
		ep11.CKA_KEY_TYPE:  ep11.CKK_AES,
		ep11.CKA_VALUE_LEN: 128 / 8,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	// Extract Bob's EC coordinates
	bobECCoordinates, err := util.GetECPointFromSPKI(bobECKeypairResponse.PubKeyBytes)
	if err != nil {
		panic(fmt.Errorf("Bob's EC key cannot obtain coordinates: %s", err))
	}

	aliceDerivekeyRequest := &pb.DeriveKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_ECDH1_DERIVE, Parameter: util.SetMechParm(bobECCoordinates)},
		Template: util.AttributeMap(deriveKeyTemplate),
		BaseKey:  aliceECKeypairResponse.PrivKey,
	}

	// Derive AES key for Alice
	aliceDerivekeyResponse, err := cryptoClient.DeriveKey(context.Background(), aliceDerivekeyRequest)
	if err != nil {
		panic(fmt.Errorf("Alice EC key derive error: %s", err))
	}

	// Extract Alice's EC coordinates
	aliceECCoordinates, err := util.GetECPointFromSPKI(aliceECKeypairResponse.PubKeyBytes)
	if err != nil {
		panic(fmt.Errorf("Alice's EC key cannot obtain coordinates: %s", err))
	}

	bobDerivekeyRequest := &pb.DeriveKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_ECDH1_DERIVE, Parameter: util.SetMechParm(aliceECCoordinates)},
		Template: util.AttributeMap(deriveKeyTemplate),
		BaseKey:  bobECKeypairResponse.PrivKey,
	}

	// Derive AES key for Bob
	bobDerivekeyResponse, err := cryptoClient.DeriveKey(context.Background(), bobDerivekeyRequest)
	if err != nil {
		panic(fmt.Errorf("Bob EC Key Derive Error: %s", err))
	}

	// Encrypt with Alice's AES key and decrypt with Bob's AES key
	var msg = []byte("hello world!")

	// Obtain initialization vector for encrypt and decrypt operations
	iv, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	encryptRequest := &pb.EncryptSingleRequest{
		Key:   aliceDerivekeyResponse.NewKey,
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Plain: msg,
	}

	// Encrypt the data using Alices's derived AES key
	encryptResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptSingle error: %s", err))
	}

	decryptRequest := &pb.DecryptSingleRequest{
		Key:      bobDerivekeyResponse.NewKey,
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Ciphered: encryptResponse.Ciphered,
	}

	// Decrypt the data using Bob's derived AES key
	decryptResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptSingle error: %s", err))
	}

	if !bytes.Equal(decryptResponse.Plain, msg) {
		panic(fmt.Errorf("Decrypted message[%v] is different from the original message: [%v]", decryptResponse.Plain, msg))
	} else {
		fmt.Println("Alice and Bob derived the same AES key")
	}

	// Output:
	// Generated Alice EC key pair
	// Generated Bob EC key pair
	// Alice and Bob derived the same AES key
}
