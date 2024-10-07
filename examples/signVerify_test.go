/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"encoding/asn1"
	"fmt"

	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/util"
)

// This file contains examples of sign and verify operations for AES, DSA, ECDSA, and RSA keys.
// Three cipher flows are demonstrated for AES, DSA, ECDSA (EC), and RSA:
// EP11 single-part (ESP), PKCS#11 single-part (PSP), and PKCS#11 multi-part (PMP)
//
// Each test name has a suffix of ESP, PSP, or PMP denoting the cipher flow used in the test.
// Refer to the ciper flow diagram in README.md.

// Example_signVerify_AES_ESP generates an AES key then signs
// a sample message and verifies the signed message using the AES key
// Flow: connect, generate AES key, sign EP11 single-part data, EP11 verify single-part data
// See "Cipher Flow 1" of the flow diagram in README.md
func Example_signVerify_AES_ESP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	keyLen := 256 // 256-bit AES key

	// Setup the AES key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_SIGN:      true,
		ep11.CKA_VERIFY:    true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated AES Key")

	signData := []byte("This data needs to be signed")

	// The following mechanisms (in variable form) can be used for AES key sign/verify operations:
	// ep11.CKM_SHA_1_HMAC
	// ep11.CKM_SHA224_HMAC
	// ep11.CKM_SHA256_HMAC -- used in this example
	// ep11.CKM_SHA384_HMAC
	// ep11.CKM_SHA512_224_HMAC
	// ep11.CKM_SHA512_256_HMAC
	// ep11.CKM_IBM_SHA512_224_HMAC
	// ep11.CKM_IBM_SHA512_256_HMAC
	// ep11.CKM_IBM_SHA3_224_HMAC -- only works with IBM Crypto Express CEX7 and CEX8 cards
	// ep11.CKM_IBM_SHA3_256_HMAC -- only works with IBM Crypto Express CEX7 and CEX8 cards
	// ep11.CKM_IBM_SHA3_384_HMAC -- only works with IBM Crypto Express CEX7 and CEX8 cards
	// ep11.CKM_IBM_SHA3_512_HMAC -- only works with IBM Crypto Express CEX7 and CEX8 cards

	signSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_SHA256_HMAC},
		PrivKey: generateKeyResponse.Key,
		Data:    signData,
	}

	// Sign the data
	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	fmt.Println("Data signed")

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_SHA256_HMAC},
		PubKey:    generateKeyResponse.Key,
		Signature: signSingleResponse.Signature,
		Data:      signData,
	}

	// Verify the data
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if err != nil {
		panic(fmt.Errorf("VerifySingle error: %s", err))
	}

	fmt.Println("Data verified")

	// Output:
	// Generated AES Key
	// Data signed
	// Data verified
}

// Example_signVerify_AES_PSP generates an AES key then signs
// a sample message and verifies the signed message using the AES key
// Flow: connect, generate AES key, sign PKCS #11 single-part data, PKCS #11 verify single-part data
// See "Cipher Flow 2" of the flow diagram in README.md
func Example_signVerify_AES_PSP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	keyLen := 256 // 256-bit AES key

	// Setup the AES key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_SIGN:      true,
		ep11.CKA_VERIFY:    true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated AES Key")

	signData := []byte("This data needs to be signed")

	// The following mechanisms (in variable form) can be used for AES key sign/verify operations:
	// ep11.CKM_SHA_1_HMAC
	// ep11.CKM_SHA224_HMAC
	// ep11.CKM_SHA256_HMAC -- used in this example
	// ep11.CKM_SHA384_HMAC
	// ep11.CKM_SHA512_224_HMAC
	// ep11.CKM_SHA512_256_HMAC
	// ep11.CKM_IBM_SHA512_224_HMAC
	// ep11.CKM_IBM_SHA512_256_HMAC
	// ep11.CKM_IBM_SHA3_224_HMAC -- only works with IBM Crypto Express CEX7 and CEX8 cards
	// ep11.CKM_IBM_SHA3_256_HMAC -- only works with IBM Crypto Express CEX7 and CEX8 cards
	// ep11.CKM_IBM_SHA3_384_HMAC -- only works with IBM Crypto Express CEX7 and CEX8 cards
	// ep11.CKM_IBM_SHA3_512_HMAC -- only works with IBM Crypto Express CEX7 and CEX8 cards

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_SHA256_HMAC},
		PrivKey: generateKeyResponse.Key,
	}

	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}

	signResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}

	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_SHA256_HMAC},
		PubKey: generateKeyResponse.Key,
	}

	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}

	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Signature: signResponse.Signature,
		Data:      signData,
	}

	_, err = cryptoClient.Verify(context.Background(), verifyRequest)
	if err != nil {
		panic(fmt.Errorf("Verify error: %s", err))
	}

	fmt.Println("Data verified")

	// Output:
	// Generated AES Key
	// Data signed
	// Data verified
}

// Example_signVerify_AES_PMP generates an AES key then signs
// a sample message and verifies the signed message using the AES key
// Flow: connect, generate AES key, sign PKCS #11 multi-part data, PKCS #11 verify multi-part data
// See "Cipher Flow 3" of the flow diagram in README.md
func Example_signVerify_AES_PMP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	keyLen := 256 // 256-bit AES key

	// Setup the AES key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_SIGN:      true,
		ep11.CKA_VERIFY:    true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated AES Key")

	signData := []byte("This data needs to be signed")

	// The following mechanisms (in variable form) can be used for AES key sign/verify operations:
	// ep11.CKM_SHA_1_HMAC
	// ep11.CKM_SHA224_HMAC
	// ep11.CKM_SHA256_HMAC -- used in this example
	// ep11.CKM_SHA384_HMAC
	// ep11.CKM_SHA512_224_HMAC
	// ep11.CKM_SHA512_256_HMAC
	// ep11.CKM_IBM_SHA512_224_HMAC
	// ep11.CKM_IBM_SHA512_256_HMAC
	// ep11.CKM_IBM_SHA3_224_HMAC -- only works with IBM Crypto Express CEX7 and CEX8 cards
	// ep11.CKM_IBM_SHA3_256_HMAC -- only works with IBM Crypto Express CEX7 and CEX8 cards
	// ep11.CKM_IBM_SHA3_384_HMAC -- only works with IBM Crypto Express CEX7 and CEX8 cards
	// ep11.CKM_IBM_SHA3_512_HMAC -- only works with IBM Crypto Express CEX7 and CEX8 cards

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_SHA256_HMAC},
		PrivKey: generateKeyResponse.Key,
	}

	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	signUpdateRequest := &pb.SignUpdateRequest{
		State: signInitResponse.State,
		Data:  signData[:8],
	}

	// SignUpdate with a portion of the data to be signed
	signUpdateResponse, err := cryptoClient.SignUpdate(context.Background(), signUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("SignUpdate error: %s", err))
	}

	signUpdateRequest = &pb.SignUpdateRequest{
		State: signUpdateResponse.State,
		Data:  signData[8:],
	}

	// SignUpdate with the remaining data to be signed
	signUpdateResponse, err = cryptoClient.SignUpdate(context.Background(), signUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("SignUpdate error: %s", err))
	}

	signFinalRequest := &pb.SignFinalRequest{
		State: signUpdateResponse.State,
	}

	// Perform SignFinal to complete the signing process
	signFinalResponse, err := cryptoClient.SignFinal(context.Background(), signFinalRequest)
	if err != nil {
		panic(fmt.Errorf("SignFinal error: %s", err))
	}

	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_SHA256_HMAC},
		PubKey: generateKeyResponse.Key,
	}

	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}

	verifyUpdateRequest := &pb.VerifyUpdateRequest{
		State: verifyInitResponse.State,
		Data:  signData[:8],
	}

	// VerifyUpdate with a portion of the data to be verifed
	verifyUpdateResponse, err := cryptoClient.VerifyUpdate(context.Background(), verifyUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyUpdate error: %s", err))
	}

	verifyUpdateRequest = &pb.VerifyUpdateRequest{
		State: verifyUpdateResponse.State,
		Data:  signData[8:],
	}

	// VerifyUpdate with the remaining data to be verified
	verifyUpdateResponse, err = cryptoClient.VerifyUpdate(context.Background(), verifyUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyUpdate error: %s", err))
	}

	verifyFinalRequest := &pb.VerifyFinalRequest{
		State:     verifyUpdateResponse.State,
		Signature: signFinalResponse.Signature,
	}

	// Perform VerifyFinal to complete the verification process
	_, err = cryptoClient.VerifyFinal(context.Background(), verifyFinalRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyFinal error: %s", err))
	}

	fmt.Println("Data verified")

	// Output:
	// Generated AES Key
	// Data signed
	// Data verified
}

// Example_signVerify_RSA_ESP generates an RSA key pair then signs
// a sample message and verifies the signed message using the RSA key pair
// Flow: connect, generate RSA key pair, sign EP11 single-part data, EP11 verify single-part data
// See "Cipher Flow 1" of the flow diagram in README.md
func Example_signVerify_RSA_ESP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Generate RSA key pair
	publicExponent := 65537
	keySize := 4096
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VERIFY:          true, // allow public key to verify signatures
		ep11.CKA_MODULUS_BITS:    keySize,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
		ep11.CKA_SIGN:      true, // allow private key to perform sign operations
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

	fmt.Println("Generated RSA key pair")

	// Non-PSS (Probabilistic Signature Scheme) Mechanisms that can be used for sign/verify operations using RSA keys:
	// ep11.CKM_RSA_PKCS
	// ep11.CKM_SHA1_RSA_PKCS
	// ep11.CKM_SHA224_RSA_PKCS
	// ep11.CKM_SHA256_RSA_PKCS
	// ep11.CKM_SHA384_RSA_PKCS
	// ep11.CKM_SHA512_RSA_PKCS -- used in this example
	// NOTE: Sign/Verify examples using PSS Mechanisms for RSA keys can be found below

	signData := []byte("This data needs to be signed")

	signSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_SHA512_RSA_PKCS},
		PrivKey: generateKeyPairResponse.PrivKey,
		Data:    signData,
	}

	// Sign the data
	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	fmt.Println("Data signed")

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_SHA512_RSA_PKCS},
		PubKey:    generateKeyPairResponse.PubKey,
		Signature: signSingleResponse.Signature,
		Data:      signData,
	}

	// Verify the data
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if err != nil {
		panic(fmt.Errorf("VerifySingle error: %s", err))
	}

	fmt.Println("Data verified")

	// Output:
	// Generated RSA key pair
	// Data signed
	// Data verified
}

// Example_signVerify_RSA_PSP generates an RSA key pair then signs
// a sample message and verifies the signed message using the RSA key pair
// Flow: connect, generate RSA key pair, sign PKCS #11 single-part data, PKCS #11 verify single-part data
// See "Cipher Flow 2" of the flow diagram in README.md
func Example_signVerify_RSA_PSP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Generate RSA key pair
	publicExponent := 65537
	keySize := 4096
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VERIFY:          true, // allow public key to verify signatures
		ep11.CKA_MODULUS_BITS:    keySize,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
		ep11.CKA_SIGN:      true, // allow private key to perform sign operations
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

	fmt.Println("Generated RSA key pair")

	// Non-PSS (Probabilistic Signature Scheme) Mechanisms that can be used for sign/verify operations using RSA keys:
	// ep11.CKM_RSA_PKCS
	// ep11.CKM_SHA1_RSA_PKCS
	// ep11.CKM_SHA224_RSA_PKCS
	// ep11.CKM_SHA56_RSA_PKCS
	// ep11.CKM_SHA384_RSA_PKCS
	// ep11.CKM_SHA512_RSA_PKCS -- used in this example
	// NOTE: Sign/Verify examples using PSS Mechanisms for RSA keys can be found below

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_SHA512_RSA_PKCS},
		PrivKey: generateKeyPairResponse.PrivKey,
	}

	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	signData := []byte("This data needs to be signed")

	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}

	// Sign the data
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}
	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_SHA512_RSA_PKCS},
		PubKey: generateKeyPairResponse.PubKey,
	}

	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}

	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: SignResponse.Signature,
	}

	// Verify the data
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}
	fmt.Println("Data verified")

	// Output:
	// Generated RSA key pair
	// Data signed
	// Data verified
}

// Example_signVerify_RSA_PMP generates an RSA key pair then signs
// a sample message and verifies the signed message using the RSA key pair
// Flow: connect, generate RSA key pair, sign PKCS #11 multi-part data, PKCS #11 verify multi-part data
// See "Cipher Flow 3" of the flow diagram in README.md
func Example_signVerify_RSA_PMP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Generate RSA key pair
	publicExponent := 65537
	keySize := 4096
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VERIFY:          true, // allow public key to verify signatures
		ep11.CKA_MODULUS_BITS:    keySize,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
		ep11.CKA_SIGN:      true, // allow private key to perform sign operations
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
	fmt.Println("Generated RSA key pair")

	// Non-PSS (Probabilistic Signature Scheme) Mechanisms that can be used for sign/verify operations using RSA keys:
	// ep11.CKM_RSA_PKCS
	// ep11.CKM_SHA1_RSA_PKCS
	// ep11.CKM_SHA224_RSA_PKCS
	// ep11.CKM_SHA56_RSA_PKCS
	// ep11.CKM_SHA384_RSA_PKCS
	// ep11.CKM_SHA512_RSA_PKCS -- used in this example
	// NOTE: Sign/Verify examples using PSS Mechanisms for RSA keys can be found below

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_SHA512_RSA_PKCS},
		PrivKey: generateKeyPairResponse.PrivKey,
	}

	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	signData := []byte("This data needs to be signed")

	signUpdateRequest := &pb.SignUpdateRequest{
		State: signInitResponse.State,
		Data:  signData[:8],
	}

	// SignUpdate with a portion of the data to be signed
	signUpdateResponse, err := cryptoClient.SignUpdate(context.Background(), signUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("SignUpdate error: %s", err))
	}

	signUpdateRequest = &pb.SignUpdateRequest{
		State: signUpdateResponse.State,
		Data:  signData[8:],
	}

	// SignUpdate with the remaining data to be signed
	signUpdateResponse, err = cryptoClient.SignUpdate(context.Background(), signUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("SignUpdate error: %s", err))
	}

	signFinalRequest := &pb.SignFinalRequest{
		State: signUpdateResponse.State,
	}

	// Perform SignFinal to complete the signing process
	signFinalResponse, err := cryptoClient.SignFinal(context.Background(), signFinalRequest)
	if err != nil {
		panic(fmt.Errorf("SignFinal error: %s", err))
	}

	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_SHA512_RSA_PKCS},
		PubKey: generateKeyPairResponse.PubKey,
	}

	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}

	verifyUpdateRequest := &pb.VerifyUpdateRequest{
		State: verifyInitResponse.State,
		Data:  signData[:8],
	}

	// VerifyUpdate with a portion of the data to be verifed
	verifyUpdateResponse, err := cryptoClient.VerifyUpdate(context.Background(), verifyUpdateRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		panic(fmt.Errorf("VerifyUpdate error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
	}

	verifyUpdateRequest = &pb.VerifyUpdateRequest{
		State: verifyUpdateResponse.State,
		Data:  signData[8:],
	}

	// VerifyUpdate with the remaining data to be verified
	verifyUpdateResponse, err = cryptoClient.VerifyUpdate(context.Background(), verifyUpdateRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		panic(fmt.Errorf("VerifyUpdate error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
	}

	verifyFinalRequest := &pb.VerifyFinalRequest{
		State:     verifyUpdateResponse.State,
		Signature: signFinalResponse.Signature,
	}

	// Perform VerifyFinal to complete the verification process
	_, err = cryptoClient.VerifyFinal(context.Background(), verifyFinalRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("VerifyFinal error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Data verified")

	// Output:
	// Generated RSA key pair
	// Data signed
	// Data verified
}

// Example_signVerify_RSA_PSS_ESP generates an RSA key pair then signs
// a sample message and verifies the signed message using the RSA key pair
// This example uses a Problemistic Signing Scheme (PSS) mechanism for signing and verifying data
// Flow: connect, generate RSA key pair, sign EP11 single-part data, EP11 verify single-part data
// See "Cipher Flow 1" of the flow diagram in README.md
func Example_signVerify_RSA_PSS_ESP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Generate RSA key pair
	publicExponent := 65537
	keySize := 4096
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VERIFY:          true, // allow public key to verify signatures
		ep11.CKA_MODULUS_BITS:    keySize,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
		ep11.CKA_SIGN:      true, // allow private key to perform sign operations
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

	fmt.Println("Generated RSA key pair")

	signData := []byte("This data needs to be signed")

	// Valid combinations of mechanism and mechanism parameter field values for PSS (must be the same for sign and verify):
	// Mechanism: ep11.CKM_RSA_PKCS_PSS         MechParm HashMech: ep11.CKM_SHA_1  MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha1
	// Mechanism: ep11.CKM_SHA1_RSA_PKCS_PSS    MechParm HashMech: ep11.CKM_SHA_1  MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha1
	// Mechanism: ep11.CKM_SHA224_RSA_PKCS_PSS  MechParm HashMech: ep11.CKM_SHA224 MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha224
	// Mechanism: ep11.CKM_SHA256_RSA_PKCS_PSS  MechParm HashMech: ep11.CKM_SHA256 MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha256
	// Mechanism: ep11.CKM_SHA384_RSA_PKCS_PSS  MechParm HashMech: ep11.CKM_SHA384 MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha384
	// Mechanism: ep11.CKM_SHA512_RSA_PKCS_PSS  MechParm HashMech: ep11.CKM_SHA512 MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha512 -- used in this example
	// NOTE: This example uses the 512 bit mechanism and mechanism parameters

	pssMechParm := &pb.RSAPSSParm{
		HashMech: ep11.CKM_SHA512,
		Mgf:      pb.RSAPSSParm_CkgMgf1Sha512,
	}

	signSingleRequest := &pb.SignSingleRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_SHA512_RSA_PKCS_PSS,
			Parameter: &pb.Mechanism_RSAPSSParameter{RSAPSSParameter: pssMechParm},
		},
		PrivKey: generateKeyPairResponse.PrivKey,
		Data:    signData,
	}

	// Sign the data
	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	fmt.Println("Data signed")

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_SHA512_RSA_PKCS_PSS,
			Parameter: &pb.Mechanism_RSAPSSParameter{RSAPSSParameter: pssMechParm},
		},
		PubKey:    generateKeyPairResponse.PubKey,
		Signature: signSingleResponse.Signature,
		Data:      signData,
	}

	// Verify the data
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if err != nil {
		panic(fmt.Errorf("VerifySingle error: %s", err))
	}

	fmt.Println("Data verified")

	// Output:
	// Generated RSA key pair
	// Data signed
	// Data verified
}

// Example_signVerify_RSA_PSS_PSP generates an RSA key pair then signs
// a sample message and verifies the signed message using the RSA key pair
// This example uses a Problemistic Signing Scheme (PSS) mechanism for signing and verifying data
// Flow: connect, generate RSA key pair, sign PKCS #11 single-part data, PKCS #11 verify single-part data
// See "Cipher Flow 2" of the flow diagram in README.md
func Example_signVerify_RSA_PSS_PSP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Generate RSA key pair
	publicExponent := 65537
	keySize := 4096
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VERIFY:          true, // allow public key to verify signatures
		ep11.CKA_MODULUS_BITS:    keySize,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
		ep11.CKA_SIGN:      true, // allow private key to perform sign operations
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

	fmt.Println("Generated RSA key pair")

	signData := []byte("This data needs to be signed")

	// Valid combinations of mechanism and mechanism parameter field values for PSS (must be the same for sign and verify):
	// Mechanism: ep11.CKM_RSA_PKCS_PSS         MechParm HashMech: ep11.CKM_SHA_1  MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha1
	// Mechanism: ep11.CKM_SHA1_RSA_PKCS_PSS    MechParm HashMech: ep11.CKM_SHA_1  MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha1
	// Mechanism: ep11.CKM_SHA224_RSA_PKCS_PSS  MechParm HashMech: ep11.CKM_SHA224 MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha224
	// Mechanism: ep11.CKM_SHA256_RSA_PKCS_PSS  MechParm HashMech: ep11.CKM_SHA256 MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha256
	// Mechanism: ep11.CKM_SHA384_RSA_PKCS_PSS  MechParm HashMech: ep11.CKM_SHA384 MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha384
	// Mechanism: ep11.CKM_SHA512_RSA_PKCS_PSS  MechParm HashMech: ep11.CKM_SHA512 MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha512 -- used in this example
	// NOTE: This example uses the 512 bit mechanism and mechanism parameters

	pssMechParm := &pb.RSAPSSParm{
		HashMech: ep11.CKM_SHA512,
		Mgf:      pb.RSAPSSParm_CkgMgf1Sha512,
	}

	signInitRequest := &pb.SignInitRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_SHA512_RSA_PKCS_PSS,
			Parameter: &pb.Mechanism_RSAPSSParameter{RSAPSSParameter: pssMechParm},
		},
		PrivKey: generateKeyPairResponse.PrivKey,
	}

	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}

	// Sign the data
	signResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}

	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_SHA512_RSA_PKCS_PSS,
			Parameter: &pb.Mechanism_RSAPSSParameter{RSAPSSParameter: pssMechParm},
		},
		PubKey: generateKeyPairResponse.PubKey,
	}

	// Verify the data
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}

	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Signature: signResponse.Signature,
		Data:      signData,
	}

	// Verify the data
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)
	if err != nil {
		panic(fmt.Errorf("Verify error: %s", err))
	}

	fmt.Println("Data verified")

	// Output:
	// Generated RSA key pair
	// Data signed
	// Data verified
}

// Example_signVerify_RSA_PSS_PMP generates an RSA key pair then signs
// a sample message and verifies the signed message using the RSA key pair
// This example uses a Problemistic Signing Scheme (PSS) mechanism for signing and verifying data
// Flow: connect, generate RSA key pair, sign PKCS #11 multi-part data, PKCS #11 verify multi-part data
// See "Cipher Flow 3" of the flow diagram in README.md
func Example_signVerify_RSA_PSS_PMP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Generate RSA key pair
	publicExponent := 65537
	keySize := 4096
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VERIFY:          true, // allow public key to verify signatures
		ep11.CKA_MODULUS_BITS:    keySize,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
		ep11.CKA_SIGN:      true, // allow private key to perform sign operations
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
	fmt.Println("Generated RSA key pair")

	// Valid combinations of mechanism and mechanism parameter field values for PSS (must be the same for sign and verify):
	// Mechanism: ep11.CKM_RSA_PKCS_PSS         MechParm HashMech: ep11.CKM_SHA_1  MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha1
	// Mechanism: ep11.CKM_SHA1_RSA_PKCS_PSS    MechParm HashMech: ep11.CKM_SHA_1  MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha1
	// Mechanism: ep11.CKM_SHA224_RSA_PKCS_PSS  MechParm HashMech: ep11.CKM_SHA224 MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha224
	// Mechanism: ep11.CKM_SHA256_RSA_PKCS_PSS  MechParm HashMech: ep11.CKM_SHA256 MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha256
	// Mechanism: ep11.CKM_SHA384_RSA_PKCS_PSS  MechParm HashMech: ep11.CKM_SHA384 MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha384
	// Mechanism: ep11.CKM_SHA512_RSA_PKCS_PSS  MechParm HashMech: ep11.CKM_SHA512 MechParm Mgf: pb.RSAPSSParm_CkgMgf1Sha512 -- used in this example
	// NOTE: This example uses the 512 bit mechanism and mechanism parameters

	pssMechParm := &pb.RSAPSSParm{
		HashMech: ep11.CKM_SHA512,
		Mgf:      pb.RSAPSSParm_CkgMgf1Sha512,
	}

	signInitRequest := &pb.SignInitRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_SHA512_RSA_PKCS_PSS,
			Parameter: &pb.Mechanism_RSAPSSParameter{RSAPSSParameter: pssMechParm},
		},
		PrivKey: generateKeyPairResponse.PrivKey,
	}

	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	signData := []byte("This data needs to be signed")

	signUpdateRequest := &pb.SignUpdateRequest{
		State: signInitResponse.State,
		Data:  signData[:8],
	}

	// SignUpdate with a portion of the data to be signed
	signUpdateResponse, err := cryptoClient.SignUpdate(context.Background(), signUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("SignUpdate error: %s", err))
	}

	signUpdateRequest = &pb.SignUpdateRequest{
		State: signUpdateResponse.State,
		Data:  signData[8:],
	}

	// SignUpdate with the remaining data to be signed
	signUpdateResponse, err = cryptoClient.SignUpdate(context.Background(), signUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("SignUpdate error: %s", err))
	}

	signFinalRequest := &pb.SignFinalRequest{
		State: signUpdateResponse.State,
	}

	// Perform SignFinal to complete the signing process
	signFinalResponse, err := cryptoClient.SignFinal(context.Background(), signFinalRequest)
	if err != nil {
		panic(fmt.Errorf("SignFinal error: %s", err))
	}

	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_SHA512_RSA_PKCS_PSS,
			Parameter: &pb.Mechanism_RSAPSSParameter{RSAPSSParameter: pssMechParm},
		},
		PubKey: generateKeyPairResponse.PubKey,
	}

	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}

	verifyUpdateRequest := &pb.VerifyUpdateRequest{
		State: verifyInitResponse.State,
		Data:  signData[:8],
	}

	// VerifyUpdate with a portion of the data to be verifed
	verifyUpdateResponse, err := cryptoClient.VerifyUpdate(context.Background(), verifyUpdateRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		panic(fmt.Errorf("VerifyUpdate error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
	}

	verifyUpdateRequest = &pb.VerifyUpdateRequest{
		State: verifyUpdateResponse.State,
		Data:  signData[8:],
	}

	// VerifyUpdate with the remaining data to be verified
	verifyUpdateResponse, err = cryptoClient.VerifyUpdate(context.Background(), verifyUpdateRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		panic(fmt.Errorf("VerifyUpdate error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
	}

	verifyFinalRequest := &pb.VerifyFinalRequest{
		State:     verifyUpdateResponse.State,
		Signature: signFinalResponse.Signature,
	}

	// Perform VerifyFinal to complete the verification process
	_, err = cryptoClient.VerifyFinal(context.Background(), verifyFinalRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("VerifyFinal error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Data verified")

	// Output:
	// Generated RSA key pair
	// Data signed
	// Data verified
}

// Example_signVerify_DSA_ESP generates a DSA key pair then signs
// the sample message and verifies the signed message using the DSA key pair
// NOTE: DSA keys only support the CKM_DSA_SHA1 mechanism for sign and verify operations
//
// Flow: connect, generate DSA key pair, sign EP11 single-part data, EP11 verify single-part data
// See "Cipher Flow 1" of the flow diagram in README.md
func Example_signVerify_DSA_ESP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	dsaDomainTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIME_BITS: 2048,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_DSA_PARAMETER_GEN},
		Template: util.AttributeMap(dsaDomainTemplate),
	}

	// First obtain DSA domain parameters that will used by the DSA GenerateKeyPair request
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}
	fmt.Println("Generated DSA domain parameters")

	// Define public and private key attributes
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_IBM_STRUCT_PARAMS: generateKeyResponse.KeyBytes, // domain parameters
		ep11.CKA_VERIFY:            true,                         // allow public key to verify signatures
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:      true, // allow private key to perform sign operations
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
	}

	// Now generate the DSA key pair using the domain parameters created in the previous step
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_DSA_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated DSA key pair")

	signData := []byte("This data needs to be signed")

	signSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_DSA_SHA1},
		PrivKey: generateKeyPairResponse.PrivKey,
		Data:    signData,
	}

	// Sign the data
	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	fmt.Println("Data signed")

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_DSA_SHA1},
		PubKey:    generateKeyPairResponse.PubKey,
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

	fmt.Println("Data verified")

	// Output:
	// Generated DSA domain parameters
	// Generated DSA key pair
	// Data signed
	// Data verified
}

// Example_signVerify_DSA_PSP generates a DSA key pair then signs
// the sample message and verifies the signed message using the DSA key pair
// Flow: connect, generate DSA key pair, sign PKCS #11 single-part data, PKCS #11 verify single-part data
// See "Cipher Flow 2" of the flow diagram in README.md
func Example_signVerify_DSA_PSP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	dsaDomainTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIME_BITS: 2048,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_DSA_PARAMETER_GEN},
		Template: util.AttributeMap(dsaDomainTemplate),
	}

	// First obtain DSA domain parameters that will used by the DSA GenerateKeyPair request
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}
	fmt.Println("Generated DSA domain parameters")

	// Define public and private key attributes
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_IBM_STRUCT_PARAMS: generateKeyResponse.KeyBytes, // domain parameters
		ep11.CKA_VERIFY:            true,                         // allow public key to verify signatures
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:      true, // allow private key to perform sign operations
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
	}

	// Now generate the DSA key pair using the domain parameters created in the previous step
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_DSA_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated DSA key pair")

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_DSA_SHA1},
		PrivKey: generateKeyPairResponse.PrivKey,
	}

	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	signData := []byte("This data needs to be signed")

	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}

	// Sign the data
	signResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}

	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_DSA_SHA1},
		PubKey: generateKeyPairResponse.PubKey,
	}

	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}

	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: signResponse.Signature,
	}

	// Verify the data
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Data verified")

	// Output:
	// Generated DSA domain parameters
	// Generated DSA key pair
	// Data signed
	// Data verified
}

// Example_signVerify_DSA_PMP generates a DSA key pair then signs
// the sample message and verifies the signed message using the DSA key pair
// Flow: connect, generate DSA key pair, sign PKCS #11 multi-part data, PKCS #11 verify multi-part data
// See "Cipher Flow 3" of the flow diagram in README.md
func Example_signVerify_DSA_PMP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	dsaDomainTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIME_BITS: 2048,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_DSA_PARAMETER_GEN},
		Template: util.AttributeMap(dsaDomainTemplate),
	}

	// First obtain DSA domain parameters that will used by the DSA GenerateKeyPair request
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}
	fmt.Println("Generated DSA domain parameters")

	// Define public and private key attributes
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_IBM_STRUCT_PARAMS: generateKeyResponse.KeyBytes, // domain parameters
		ep11.CKA_VERIFY:            true,                         // allow public key to verify signatures
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:      true, // allow private key to perform sign operations
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
	}

	// Now generate the DSA key pair using the domain parameters created in the previous step
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_DSA_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated DSA key pair")

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_DSA_SHA1},
		PrivKey: generateKeyPairResponse.PrivKey,
	}

	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	signData := []byte("This data needs to be signed")

	signUpdateRequest := &pb.SignUpdateRequest{
		State: signInitResponse.State,
		Data:  signData[:8],
	}

	// SignUpdate with a portion of the data to be signed
	signUpdateResponse, err := cryptoClient.SignUpdate(context.Background(), signUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("SignUpdate error: %s", err))
	}

	signUpdateRequest = &pb.SignUpdateRequest{
		State: signUpdateResponse.State,
		Data:  signData[8:],
	}

	// SignUpdate with the remaining data to be signed
	signUpdateResponse, err = cryptoClient.SignUpdate(context.Background(), signUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("SignUpdate error: %s", err))
	}

	signFinalRequest := &pb.SignFinalRequest{
		State: signUpdateResponse.State,
	}

	// Perform SignFinal to complete the signing process
	signFinalResponse, err := cryptoClient.SignFinal(context.Background(), signFinalRequest)
	if err != nil {
		panic(fmt.Errorf("SignFinal error: %s", err))
	}

	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_DSA_SHA1},
		PubKey: generateKeyPairResponse.PubKey,
	}

	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}

	verifyUpdateRequest := &pb.VerifyUpdateRequest{
		State: verifyInitResponse.State,
		Data:  signData[:8],
	}

	// VerifyUpdate with a portion of the data to be verifed
	verifyUpdateResponse, err := cryptoClient.VerifyUpdate(context.Background(), verifyUpdateRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		panic(fmt.Errorf("VerifyUpdate error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
	}

	verifyUpdateRequest = &pb.VerifyUpdateRequest{
		State: verifyUpdateResponse.State,
		Data:  signData[8:],
	}

	// VerifyUpdate with the remaining data to be verified
	verifyUpdateResponse, err = cryptoClient.VerifyUpdate(context.Background(), verifyUpdateRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		panic(fmt.Errorf("VerifyUpdate error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
	}

	verifyFinalRequest := &pb.VerifyFinalRequest{
		State:     verifyUpdateResponse.State,
		Signature: signFinalResponse.Signature,
	}

	// Perform VerifyFinal to complete the verification process
	_, err = cryptoClient.VerifyFinal(context.Background(), verifyFinalRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("VerifyFinal error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Data verified")

	// Output:
	// Generated DSA domain parameters
	// Generated DSA key pair
	// Data signed
	// Data verified
}

// Example_signVerify_ECDSA_ESP generates an ECDSA key pair
// then uses the key pair to sign and verify a sample message
// Flow: connect, generate ECDSA key pair, sign EP11 single-part data, verify EP11 single-part data
// See "Cipher Flow 1" of the flow diagram in README.md
func Example_signVerify_ECDSA_ESP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// EC Curve variables that can be used with the CKM_ECDSA signing mechanism:
	// util.OIDNamedCurveSecp256k1 -- used in this example
	// util.OIDNamedCurveP224
	// util.OIDNamedCurveP256
	// util.OIDNamedCurveP384
	// util.OIDNamedCurveP521
	// util.OIDBrainpoolP160r1
	// util.OIDBrainpoolP192r1
	// util.OIDBrainpoolP224r1
	// util.OIDBrainpoolP256r1
	// util.OIDBrainpoolP320r1
	// util.OIDBrainpoolP384r1
	// util.OIDBrainpoolP160t1
	// util.OIDBrainpoolP192t1
	// util.OIDBrainpoolP224t1
	// util.OIDBrainpoolP256t1
	// util.OIDBrainpoolP320t1
	// util.OIDBrainpoolP384t1

	ecParameters, err := asn1.Marshal(util.OIDNamedCurveSecp256k1)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	publicKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_EC_PARAMS: ecParameters,
		ep11.CKA_VERIFY:    true, // allow public key to verify signatures
	}

	privateKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:      true, // allow private key to perform sign operations
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
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

	fmt.Println("Generated ECDSA key pair")

	signData := []byte("This data needs to be signed")

	signSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: generateKeyPairResponse.PrivKey,
		Data:    signData,
	}

	// Sign the data
	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	fmt.Println("Data signed")

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey:    generateKeyPairResponse.PubKey,
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

	fmt.Println("Data verified")

	// Output:
	// Generated ECDSA key pair
	// Data signed
	// Data verified
}

// Example_signVerify_ECDSA_PSP generates an ECDSA key pair
// then uses the key pair to sign and verify a sample message
// Flow: connect, generate ECDSA key pair, sign PKCS #11 single-part data, verify PKCS #11 single-part data
// See "Cipher Flow 2" of the flow diagram in README.md
func Example_signVerify_ECDSA_PSP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// EC Curve variables that can be used with the CKM_ECDSA signing mechanism:
	// util.OIDNamedCurveSecp256k1 -- used in this example
	// util.OIDNamedCurveP224
	// util.OIDNamedCurveP256
	// util.OIDNamedCurveP384
	// util.OIDNamedCurveP521
	// util.OIDBrainpoolP160r1
	// util.OIDBrainpoolP192r1
	// util.OIDBrainpoolP224r1
	// util.OIDBrainpoolP256r1
	// util.OIDBrainpoolP320r1
	// util.OIDBrainpoolP384r1
	// util.OIDBrainpoolP160t1
	// util.OIDBrainpoolP192t1
	// util.OIDBrainpoolP224t1
	// util.OIDBrainpoolP256t1
	// util.OIDBrainpoolP320t1
	// util.OIDBrainpoolP384t1

	ecParameters, err := asn1.Marshal(util.OIDNamedCurveSecp256k1)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	publicKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_EC_PARAMS: ecParameters,
		ep11.CKA_VERIFY:    true, // allow public key to verify signatures
	}

	privateKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:      true, // allow private key to perform sign operations
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
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

	fmt.Println("Generated ECDSA key pair")

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: generateKeyPairResponse.PrivKey,
	}

	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	signData := []byte("This data needs to be signed")

	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}

	// Sign the data
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}

	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey: generateKeyPairResponse.PubKey,
	}

	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}

	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: SignResponse.Signature,
	}

	// Verify the data
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Data verified")

	// Output:
	// Generated ECDSA key pair
	// Data signed
	// Data verified
}

// Example_signVerify_ECDSA_PMP generates an ECDSA key pair
// then uses the key pair to sign and verify a sample message
// Flow: connect, generate ECDSA key pair, sign PKCS #11 multi-part data, verify PKCS #11 multi-part data
// See "Cipher Flow 3" of the flow diagram in README.md
//
// NOTE: Elliptic Curve (EC) keys can only use hashing ECDSA mechanisms for PKCS#11 multi-part sign and verify
// operations.  As a result the CKM_ECDSA mechanism used in the EP11 single-part and PKCS#11 single-part sign/verify
// examples above cannot be used in this example.  A hashing ECDSA mechanism must be used for PKCS#11 multi-part
// sign and verify operations.  The possible list of hashing ECDSA mechanisms (in variable form) are:
// ep11.CKM_ECDSA_SHA1
// ep11.CKM_ECDSA_SHA224
// ep11.CKM_ECDSA_SHA256
// ep11.CKM_ECDSA_SHA384
// ep11.CKM_ECDSA_SHA512
// ep11.CKM_IBM_ECDSA_SHA224
// ep11.CKM_IBM_ECDSA_SHA256
// ep11.CKM_IBM_ECDSA_SHA384
// ep11.CKM_IBM_ECDSA_SHA512
//
// The example below uses the ep11.CKM_ECDSA_SHA512 mechanism
func Example_signVerify_ECDSA_PMP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// EC Curve variables that can be used with the CKM_ECDSA signing mechanism:
	// util.OIDNamedCurveSecp256k1
	// util.OIDNamedCurveP224
	// util.OIDNamedCurveP256 -- used in this example
	// util.OIDNamedCurveP384
	// util.OIDNamedCurveP521
	// util.OIDBrainpoolP160r1
	// util.OIDBrainpoolP192r1
	// util.OIDBrainpoolP224r1
	// util.OIDBrainpoolP256r1
	// util.OIDBrainpoolP320r1
	// util.OIDBrainpoolP384r1
	// util.OIDBrainpoolP160t1
	// util.OIDBrainpoolP192t1
	// util.OIDBrainpoolP224t1
	// util.OIDBrainpoolP256t1
	// util.OIDBrainpoolP320t1
	// util.OIDBrainpoolP384t1

	ecParameters, err := asn1.Marshal(util.OIDNamedCurveP256)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	publicKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_EC_PARAMS: ecParameters,
		ep11.CKA_VERIFY:    true, // allow public key to verify signatures
	}

	privateKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:      true, // allow private key to perform sign operations
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
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

	fmt.Println("Generated ECDSA key pair")

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA_SHA512},
		PrivKey: generateKeyPairResponse.PrivKey,
	}

	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	signData := []byte("This data needs to be signed")

	signUpdateRequest := &pb.SignUpdateRequest{
		State: signInitResponse.State,
		Data:  signData[:8],
	}

	// SignUpdate with a portion of the data to be signed
	signUpdateResponse, err := cryptoClient.SignUpdate(context.Background(), signUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("SignUpdate error: %s", err))
	}

	signUpdateRequest = &pb.SignUpdateRequest{
		State: signUpdateResponse.State,
		Data:  signData[8:],
	}

	// SignUpdate with the remaining data to be signed
	signUpdateResponse, err = cryptoClient.SignUpdate(context.Background(), signUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("SignUpdate error: %s", err))
	}

	signFinalRequest := &pb.SignFinalRequest{
		State: signUpdateResponse.State,
	}

	// Perform SignFinal to complete the signing process
	signFinalResponse, err := cryptoClient.SignFinal(context.Background(), signFinalRequest)
	if err != nil {
		panic(fmt.Errorf("SignFinal error: %s", err))
	}

	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_ECDSA_SHA512},
		PubKey: generateKeyPairResponse.PubKey,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}

	verifyUpdateRequest := &pb.VerifyUpdateRequest{
		State: verifyInitResponse.State,
		Data:  signData[:8],
	}

	// VerifyUpdate with a portion of the data to be verifed
	verifyUpdateResponse, err := cryptoClient.VerifyUpdate(context.Background(), verifyUpdateRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		panic(fmt.Errorf("VerifyUpdate error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
	}

	verifyUpdateRequest = &pb.VerifyUpdateRequest{
		State: verifyUpdateResponse.State,
		Data:  signData[8:],
	}

	// VerifyUpdate with the remaining data to be verified
	verifyUpdateResponse, err = cryptoClient.VerifyUpdate(context.Background(), verifyUpdateRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		panic(fmt.Errorf("VerifyUpdate error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
	}

	verifyFinalRequest := &pb.VerifyFinalRequest{
		State:     verifyUpdateResponse.State,
		Signature: signFinalResponse.Signature,
	}

	// Perform VerifyFinal to complete the verification process
	_, err = cryptoClient.VerifyFinal(context.Background(), verifyFinalRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("VerifyFinal error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Data verified")

	// Output:
	// Generated ECDSA key pair
	// Data signed
	// Data verified
}

// Example_signVerify_TestErrorHandling signs some data, modifies the signature and verifies the expected returned error code
// Flow: connect, generate ECDSA key pair, sign PKCS #11 single-part data, modify signature to force verify error,
// verify PKCS #11 single-part data, ensure proper error is returned
func Example_signVerify_TestErrorHandling() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	ecParameters, err := asn1.Marshal(util.OIDNamedCurveP256)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_EC_PARAMS: ecParameters,
		ep11.CKA_VERIFY:    true,
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:      true,
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
	}

	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated EC key pair")

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: generateKeyPairResponse.PrivKey,
	}

	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	// Sign the data
	signData := []byte("This data needs to be signed")
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}

	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}

	fmt.Println("Data signed")

	// Modify signature to force returned error code
	SignResponse.Signature[0] = 255

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey: generateKeyPairResponse.PubKey,
	}

	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}

	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: SignResponse.Signature,
	}

	// Verify the data -- expect an error
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)

	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Printf("Invalid signature\n")
			return
		}
		panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
	}

	// Output:
	// Generated EC key pair
	// Data signed
	// Invalid signature
}
