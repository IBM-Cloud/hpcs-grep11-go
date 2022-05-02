/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"testing"

	"github.com/IBM-Cloud/hpcs-grep11-go/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/util"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// The examples in this file demonstrate various flows used to perform cryptographic operations
// There are three cipher flows: EP11 single-part, PKCS #11 single-part, and PKCS #11 multi-part
// See the cipher flow diagram contained in the README.md file of this repository for additional information

// The following IBM Cloud HPCS service items need to be changed prior to running the sample program
var (
	Address     = "<grep11_server_address>:<port>"
	APIKey      = "<ibm_cloud_apikey>"
	IAMEndpoint = "https://iam.cloud.ibm.com"
)

var callOpts = []grpc.DialOption{
	grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
	grpc.WithPerRPCCredentials(&util.IAMPerRPCCredentials{
		APIKey:   APIKey,
		Endpoint: IAMEndpoint,
	}),
}

// Example_getMechanismInfo retrieves a mechanism list and retrieves detailed information for the CKM_RSA_PKCS mechanism
// Flow: connect, get mechanism list, get mechanism info
func Example_getMechanismInfo() {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	mechanismListRequest := &pb.GetMechanismListRequest{}

	// Retrieve a list of all supported mechanisms
	mechanismListResponse, err := cryptoClient.GetMechanismList(context.Background(), mechanismListRequest)
	if err != nil {
		panic(fmt.Errorf("Get mechanism list error: %s", err))
	}
	fmt.Printf("Got mechanism list:\n%v ...\n", mechanismListResponse.Mechs[:1])

	mechanismInfoRequest := &pb.GetMechanismInfoRequest{
		Mech: ep11.CKM_RSA_PKCS,
	}

	// Retrieve information about the CKM_RSA_PKCS mechanism
	mechanismInfoResponse, err := cryptoClient.GetMechanismInfo(context.Background(), mechanismInfoRequest)
	if err != nil {
		panic(fmt.Errorf("Get mechanism info error: %s", err))
	}

	_ = mechanismInfoResponse // simulate use of mechanismInfoResponse

	// Output:
	// Got mechanism list:
	// [CKM_RSA_PKCS] ...
}

// Example_generateGenericKey creates a generic key
// Generic keys can be used to derive new keys
// Flow: connect, generate generic key
func Example_generateGenericKey() {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)
	keyLen := 128 // bits
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_KEY_TYPE:    ep11.CKK_GENERIC_SECRET,
		ep11.CKA_CLASS:       ep11.CKO_SECRET_KEY,
		ep11.CKA_VALUE_LEN:   keyLen / 8,
		ep11.CKA_EXTRACTABLE: false,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_GENERIC_SECRET_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}

	_ = generateKeyResponse // simulates the use of the Generic key

	fmt.Println("Generated Generic Key")

	// Output:
	// Generated Generic Key
}

// Example_encryptAndDecryptUsingAES generates an AES key then encrypts and decrypts plain text using the generated AES key
// Flow: connect, generate AES key, generate IV, encrypt PKCS #11 multi-part data, decrypt PKCS #11 multi-part data
func Example_encryptAndDecryptUsingAES() {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)
	keyLen := 128

	// Setup the AES key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN:   keyLen / 8,
		ep11.CKA_WRAP:        false,
		ep11.CKA_UNWRAP:      false,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: false, // set to false!
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

	rngTemplate := &pb.GenerateRandomRequest{
		Len: (uint64)(ep11.AES_BLOCK_SIZE),
	}

	// Generate 16 bytes of random data for the initialization vector
	rng, err := cryptoClient.GenerateRandom(context.Background(), rngTemplate)
	if err != nil {
		panic(fmt.Errorf("GenerateRandom Error: %s", err))
	}
	iv := rng.Rnd[:ep11.AES_BLOCK_SIZE]
	fmt.Println("Generated IV")

	encryptInitRequest := &pb.EncryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:  generateKeyResponse.KeyBytes, // you may want to store this
	}

	encryptInitResponse, err := cryptoClient.EncryptInit(context.Background(), encryptInitRequest)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptInit [%s]", err))
	}

	plain := []byte("Hello, this is a very long and creative message")

	encryptUpdateRequest := &pb.EncryptUpdateRequest{
		State: encryptInitResponse.State,
		Plain: plain[:20],
	}
	encryptUpdateResponse, err := cryptoClient.EncryptUpdate(context.Background(), encryptUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptUpdate [%s]", err))
	}

	ciphertext := encryptUpdateResponse.Ciphered[:]
	encryptUpdateRequest = &pb.EncryptUpdateRequest{
		State: encryptUpdateResponse.State,
		Plain: plain[20:],
	}
	encryptUpdateResponse, err = cryptoClient.EncryptUpdate(context.Background(), encryptUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptUpdate [%s]", err))
	}

	ciphertext = append(ciphertext, encryptUpdateResponse.Ciphered...)
	encryptFinalRequest := &pb.EncryptFinalRequest{
		State: encryptUpdateResponse.State,
	}
	encryptFinalResponse, err := cryptoClient.EncryptFinal(context.Background(), encryptFinalRequest)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptFinal [%s]", err))
	}

	ciphertext = append(ciphertext, encryptFinalResponse.Ciphered...)
	fmt.Println("Encrypted message")

	decryptInitRequest := &pb.DecryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:  generateKeyResponse.KeyBytes,
	}
	decryptInitResponse, err := cryptoClient.DecryptInit(context.Background(), decryptInitRequest)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptInit [%s]", err))
	}

	decryptUpdateRequest := &pb.DecryptUpdateRequest{
		State:    decryptInitResponse.State,
		Ciphered: ciphertext[:16],
	}
	decryptUpdateResponse, err := cryptoClient.DecryptUpdate(context.Background(), decryptUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptUpdate [%s]", err))
	}

	plaintext := decryptUpdateResponse.Plain[:]
	decryptUpdateRequest = &pb.DecryptUpdateRequest{
		State:    decryptUpdateResponse.State,
		Ciphered: ciphertext[16:],
	}
	decryptUpdateResponse, err = cryptoClient.DecryptUpdate(context.Background(), decryptUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptUpdate [%s]", err))
	}
	plaintext = append(plaintext, decryptUpdateResponse.Plain...)

	decryptFinalRequest := &pb.DecryptFinalRequest{
		State: decryptUpdateResponse.State,
	}
	decryptFinalResponse, err := cryptoClient.DecryptFinal(context.Background(), decryptFinalRequest)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptFinal [%s]", err))
	}
	plaintext = append(plaintext, decryptFinalResponse.Plain...)

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing plain text of cipher single"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)

	// Output:
	// Generated AES Key
	// Generated IV
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message
}

// Example_digest calculates the digest of some plain text
// Flow: connect, digest PKCS #11 single-part data, digest PKCS #11 multi-part data
func Example_digest() {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	digestData := []byte("This is data that is longer than 64 bytes. This is the data that is longer than 64 bytes.")
	digestInitRequest := &pb.DigestInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_SHA256},
	}
	digestInitResponse, err := cryptoClient.DigestInit(context.Background(), digestInitRequest)
	if err != nil {
		panic(fmt.Errorf("Digest init error: %s", err))
	}
	digestRequest := &pb.DigestRequest{
		State: digestInitResponse.State,
		Data:  digestData,
	}
	digestResponse, err := cryptoClient.Digest(context.Background(), digestRequest)
	if err != nil {
		panic(fmt.Errorf("Digest error: %s", err))
	} else {
		fmt.Printf("Digest data using a single digest operation: %x\n", digestResponse.Digest)
	}

	// Digest using mutiple operations
	digestInitResponse, err = cryptoClient.DigestInit(context.Background(), digestInitRequest)
	if err != nil {
		panic(fmt.Errorf("DigestInit error: %s", err))
	}
	digestUpdateRequest := &pb.DigestUpdateRequest{
		State: digestInitResponse.State,
		Data:  digestData[:64],
	}
	digestUpdateResponse, err := cryptoClient.DigestUpdate(context.Background(), digestUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("DigestUpdate error: %s", err))
	}
	digestUpdateRequest = &pb.DigestUpdateRequest{
		State: digestUpdateResponse.State,
		Data:  digestData[64:],
	}
	digestUpdateResponse, err = cryptoClient.DigestUpdate(context.Background(), digestUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("DigestUpdate error: %s", err))
	}
	digestFinalRequestInfo := &pb.DigestFinalRequest{
		State: digestUpdateResponse.State,
	}
	digestFinalResponse, err := cryptoClient.DigestFinal(context.Background(), digestFinalRequestInfo)
	if err != nil {
		panic(fmt.Errorf("DigestFinal error: %s", err))
	} else {
		fmt.Printf("Digest data using multiple operations: %x\n", digestFinalResponse.Digest)
	}

	// Output:
	// Digest data using a single digest operation: b036abead70a9739648ab94d556bf120494eab3a470b5ee12be559b9dbc8c408
	// Digest data using multiple operations: b036abead70a9739648ab94d556bf120494eab3a470b5ee12be559b9dbc8c408
}

// Example_signAndVerifyUsingRSAKeyPair generates an RSA key pair then signs
// a sample message and verifies the signed message using the RSA key pair
// Flow: connect, generate RSA key pair, sign PKCS #11 single-part data, PKCS #11 verify single-part data
func Example_signAndVerifyUsingRSAKeyPair() {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	// Generate RSA key pair
	publicExponent := 17
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_ENCRYPT:         true,
		ep11.CKA_VERIFY:          true, // to verify a signature
		ep11.CKA_MODULUS_BITS:    2048,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
		ep11.CKA_EXTRACTABLE:     false,
	}
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:     true,
		ep11.CKA_SENSITIVE:   true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_SIGN:        true, // to generate a signature
		ep11.CKA_EXTRACTABLE: false,
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

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_SHA1_RSA_PKCS},
		PrivKey: generateKeyPairResponse.PrivKeyBytes,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	signData := sha256.Sum256([]byte("This data needs to be signed"))
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  []byte(signData[:]),
	}

	// Sign the data
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}
	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_SHA1_RSA_PKCS},
		PubKey: generateKeyPairResponse.PubKeyBytes,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      []byte(signData[:]),
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
	fmt.Println("Verified")

	// Output:
	// Generated RSA PKCS key pair
	// Data signed
	// Verified
}

// Example_signAndVerifyUsingDSAKeyPair generates a DSA key pair then signs
// the sample message and verifies the signed message using the DSA key pair
// Flow: connect, generate DSA key pair, sign PKCS #11 single-part data, PKCS #11 verify single-part data
func Example_signAndVerifyUsingDSAKeyPair() {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

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

	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VERIFY:            true, // to verify a signature
		ep11.CKA_EXTRACTABLE:       false,
		ep11.CKA_IBM_STRUCT_PARAMS: generateKeyResponse.KeyBytes,
	}
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:        true, // to generate a signature
		ep11.CKA_PRIVATE:     true,
		ep11.CKA_SENSITIVE:   true,
		ep11.CKA_EXTRACTABLE: false,
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
		PrivKey: generateKeyPairResponse.PrivKeyBytes,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	signData := sha256.Sum256([]byte("This data needs to be signed"))
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  []byte(signData[:]),
	}

	// Sign the data
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}
	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_DSA_SHA1},
		PubKey: generateKeyPairResponse.PubKeyBytes,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      []byte(signData[:]),
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
	fmt.Println("Verified")

	// Output:
	// Generated DSA domain parameters
	// Generated DSA key pair
	// Data signed
	// Verified
}

// Example_deriveKeyUsingDHKeyPair derives keys and shares encrypted message between two users
// Flow: connect, generate Diffie-Hellman key pairs, derive keys from Diffie-Hellman key pairs, share encypted message
func Example_deriveKeyUsingDHKeyPair() {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	dhDomainTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIME_BITS: 2048,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_DH_PKCS_PARAMETER_GEN},
		Template: util.AttributeMap(dhDomainTemplate),
	}

	// Create Diffie-Hellman domain parameters for Alice and Bob to use. They will used by the Diffie-Hellman GenerateKeyPair requests.
	commonGenerateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}
	fmt.Println("Generated Diffie-Hellman domain parameters for Alice and Bob")

	commonPublicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_DERIVE:            true, // to verify a signature
		ep11.CKA_EXTRACTABLE:       false,
		ep11.CKA_IBM_STRUCT_PARAMS: commonGenerateKeyResponse.KeyBytes,
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_DERIVE:      true, // to generate a signature
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
	alicPublicKey := util.DHPubKeyASN{}
	_, err = asn1.Unmarshal(aliceGenerateKeyPairResponse.PubKeyBytes, &alicPublicKey)
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

	_, err = asn1.Unmarshal(alicPublicKey.PublicKey.Bytes, &bigIntData)
	if err != nil {
		panic(fmt.Errorf("Failed to unmarshal Alice's public key integer: %s", err))
	}
	alicePubInteger := bigIntData.Bytes()

	aliceDeriveKeyRequest := &pb.DeriveKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_DH_PKCS_DERIVE, Parameter: util.SetMechParm(bobPubInteger)},
		Template: util.AttributeMap(deriveKeyTemplate),
		BaseKey:  aliceGenerateKeyPairResponse.PrivKeyBytes,
	}
	aliceDeriveKeyResponse, err := cryptoClient.DeriveKey(context.Background(), aliceDeriveKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Key derive error: %s", err))
	}

	fmt.Println("Key derived for Alice")

	bobDeriveKeyRequest := &pb.DeriveKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_DH_PKCS_DERIVE, Parameter: util.SetMechParm(alicePubInteger)},
		Template: util.AttributeMap(deriveKeyTemplate),
		BaseKey:  bobGenerateKeyPairResponse.PrivKeyBytes,
	}
	bobDeriveKeyResponse, err := cryptoClient.DeriveKey(context.Background(), bobDeriveKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Key derive error: %s", err))
	}

	fmt.Println("Key derived for Bob")

	// Encrypt with Alice's key and decrypt with Bob's key
	var msg = []byte("hello world!")
	rngTemplate := &pb.GenerateRandomRequest{
		Len: (uint64)(ep11.AES_BLOCK_SIZE),
	}
	rng, err := cryptoClient.GenerateRandom(context.Background(), rngTemplate)
	if err != nil {
		panic(fmt.Errorf("GenerateRandom error: %s", err))
	}
	iv := rng.Rnd[:ep11.AES_BLOCK_SIZE]
	encryptRequest := &pb.EncryptSingleRequest{
		Key:   aliceDeriveKeyResponse.NewKeyBytes,
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Plain: msg,
	}
	encryptResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptRequest)
	if err != nil {
		panic(fmt.Errorf("Encrypt error: %s", err))
	}

	decryptRequest := &pb.DecryptSingleRequest{
		Key:      bobDeriveKeyResponse.NewKeyBytes,
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Ciphered: encryptResponse.Ciphered,
	}
	decryptResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptRequest)
	if err != nil {
		panic(fmt.Errorf("Decrypt error: %s", err))
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

// Example_signAndVerifyUsingECDSAKeyPair generates an ECDSA key pair
// then uses the key pair to sign and verify a sample message
// Flow: connect, generate ECDSA key pair, sign PKCS #11 single-part data, verify PKCS #11 single-part data
func Example_signAndVerifyUsingECDSAKeyPair() {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	ecParameters, err := asn1.Marshal(util.OIDNamedCurveP256)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	publicKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_EC_PARAMS:   ecParameters,
		ep11.CKA_VERIFY:      true,
		ep11.CKA_EXTRACTABLE: false,
	}
	privateKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:        true,
		ep11.CKA_EXTRACTABLE: false,
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

	fmt.Println("Generated ECDSA PKCS key pair")

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: generateKeyPairResponse.PrivKeyBytes,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}
	signData := sha256.Sum256([]byte("This data needs to be signed"))
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData[:],
	}

	// Sign the data
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}
	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey: generateKeyPairResponse.PubKeyBytes,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      []byte(signData[:]),
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
	fmt.Println("Verified")

	// Output:
	// Generated ECDSA PKCS key pair
	// Data signed
	// Verified
}

// Example_signAndVerifyToTestErrorHandling signs some data, modifies the signature and verifies the expected returned error code
// Flow: connect, generate ECDSA key pair, sign PKCS #11 single-part data, modify signature to force verify error,
//                verify PKCS #11 single-part data, ensure proper error is returned
func Example_signAndVerifyToTestErrorHandling() {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	ecParameters, err := asn1.Marshal(util.OIDNamedCurveP256)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_EC_PARAMS:   ecParameters,
		ep11.CKA_VERIFY:      true,
		ep11.CKA_EXTRACTABLE: false,
	}
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:        true,
		ep11.CKA_EXTRACTABLE: false,
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

	fmt.Println("Generated ECDSA key pair")

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: generateKeyPairResponse.PrivKeyBytes,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	// Sign the data
	signData := sha256.Sum256([]byte("This data needs to be signed"))
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData[:],
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
		PubKey: generateKeyPairResponse.PubKeyBytes,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      []byte(signData[:]),
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
	// Generated ECDSA key pair
	// Data signed
	// Invalid signature
}

// Example_wrapAndUnWrapKey wraps an AES key with a RSA public key and then unwraps it with the RSA private key
// Flow: connect, generate AES key, generate RSA key pair, wrap/unwrap AES key with RSA key pair
func Example_wrapAndUnwrapKey() {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

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

	// Generate RSA key pairs
	publicExponent := 17
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_ENCRYPT:         true,
		ep11.CKA_WRAP:            true, // to wrap a key
		ep11.CKA_MODULUS_BITS:    2048,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
		ep11.CKA_EXTRACTABLE:     false,
	}
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:     true,
		ep11.CKA_SENSITIVE:   true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_UNWRAP:      true, // to unwrap a key
		ep11.CKA_EXTRACTABLE: false,
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
		KeK:  generateKeyPairResponse.PubKeyBytes,
		Key:  generateKeyResponse.KeyBytes,
	}

	// Wrap the AES key
	wrapKeyResponse, err := cryptoClient.WrapKey(context.Background(), wrapKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Wrap AES key error: %s", err))
	}
	fmt.Println("Wrapped AES key")

	aesUnwrapKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:       ep11.CKO_SECRET_KEY,
		ep11.CKA_KEY_TYPE:    ep11.CKK_AES,
		ep11.CKA_VALUE_LEN:   128 / 8,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: true, // must be true to be wrapped
	}
	unwrapRequest := &pb.UnwrapKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		KeK:      generateKeyPairResponse.PrivKeyBytes,
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

// Example_deriveKey generates ECDHE key pairs for Alice and Bob and then derives AES keys for both of them.
// The names Bob and Alice are described in https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange.
// Flow: connect, generate key pairs for Alice and Bob, derive AES key for Bob, derive AES key for Alice,
//       encrypt with Alice's AES key and decrypt with Bob's AES key
func Example_deriveKey() {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	// Generate ECDH key pairs for Alice and Bob
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
	combinedCoordinates, err := util.GetPubkeyBytesFromSPKI(bobECKeypairResponse.PubKeyBytes)
	if err != nil {
		panic(fmt.Errorf("Bob's EC key cannot obtain coordinates: %s", err))
	}
	aliceDerivekeyRequest := &pb.DeriveKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_ECDH1_DERIVE, Parameter: util.SetMechParm(combinedCoordinates)},
		Template: util.AttributeMap(deriveKeyTemplate),
		BaseKey:  aliceECKeypairResponse.PrivKeyBytes,
	}

	// Derive AES key for Alice
	aliceDerivekeyResponse, err := cryptoClient.DeriveKey(context.Background(), aliceDerivekeyRequest)
	if err != nil {
		panic(fmt.Errorf("Alice EC key derive error: %s", err))
	}

	// Extract Alice's EC coordinates
	combinedCoordinates, err = util.GetPubkeyBytesFromSPKI(aliceECKeypairResponse.PubKeyBytes)
	if err != nil {
		panic(fmt.Errorf("Alice's EC key cannot obtain coordinates: %s", err))
	}
	bobDerivekeyRequest := &pb.DeriveKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_ECDH1_DERIVE, Parameter: util.SetMechParm(combinedCoordinates)},
		Template: util.AttributeMap(deriveKeyTemplate),
		BaseKey:  bobECKeypairResponse.PrivKeyBytes,
	}

	// Derive AES key for Bob
	bobDerivekeyResponse, err := cryptoClient.DeriveKey(context.Background(), bobDerivekeyRequest)
	if err != nil {
		panic(fmt.Errorf("Bob EC Key Derive Error: %s", err))
	}

	// Encrypt with Alice's AES key and decrypt with Bob's AES key
	var msg = []byte("hello world!")
	rngTemplate := &pb.GenerateRandomRequest{
		Len: (uint64)(ep11.AES_BLOCK_SIZE),
	}

	// Generate a 16 byte initialization vector for the encrypt/decrypt operations
	rng, err := cryptoClient.GenerateRandom(context.Background(), rngTemplate)
	if err != nil {
		panic(fmt.Errorf("GenerateRandom error: %s", err))
	}
	iv := rng.Rnd[:ep11.AES_BLOCK_SIZE]
	encryptRequest := &pb.EncryptSingleRequest{
		Key:   aliceDerivekeyResponse.NewKeyBytes,
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Plain: msg,
	}

	// Encrypt the data using Alices's derived AES key
	encryptResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptRequest)
	if err != nil {
		panic(fmt.Errorf("Encrypt error: %s", err))
	}

	decryptRequest := &pb.DecryptSingleRequest{
		Key:      bobDerivekeyResponse.NewKeyBytes,
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Ciphered: encryptResponse.Ciphered,
	}

	// Decrypt the data using Bob's derived AES key
	decryptResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptRequest)
	if err != nil {
		panic(fmt.Errorf("Decrypt error: %s", err))
	}

	if !bytes.Equal(decryptResponse.Plain, msg) {
		panic(fmt.Errorf("Decrypted message[%v] is different from the original message: [%v]", decryptResponse.Plain, msg))
	} else {
		fmt.Println("Alice and Bob get the same derived key")
	}

	// Output:
	// Generated Alice EC key pair
	// Generated Bob EC key pair
	// Alice and Bob get the same derived key
}

// Example_wrapAndUnWrapAttributeBoundKey wraps an AES key with a RSA public key and then unwraps it with the RSA private key
// Flow: connect, generate generic symmetric key for MAC use, generate AES key, generate RSA key pair, wrap/unwrap AES key with RSA key pair
func Example_wrapAndUnwrapAttributeBoundKey() {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	// Create MAC Key
	keyLen := 128 // bits
	macKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_KEY_TYPE:      ep11.CKK_GENERIC_SECRET,
		ep11.CKA_CLASS:         ep11.CKO_SECRET_KEY,
		ep11.CKA_VALUE_LEN:     keyLen / 8,
		ep11.CKA_EXTRACTABLE:   false,
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
		ep11.CKA_VALUE_LEN:     128 / 8,
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

	// Generate RSA key pairs
	publicExponent := 17
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_ENCRYPT:         true,
		ep11.CKA_WRAP:            true, // to wrap a key
		ep11.CKA_MODULUS_BITS:    2048,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
		ep11.CKA_EXTRACTABLE:     false,
		ep11.CKA_IBM_ATTRBOUND:   true,
	}
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:       true,
		ep11.CKA_SENSITIVE:     true,
		ep11.CKA_DECRYPT:       true,
		ep11.CKA_UNWRAP:        true, // to unwrap a key
		ep11.CKA_EXTRACTABLE:   false,
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
		KeK:    generateKeyPairResponse.PubKeyBytes,
		Key:    generateKeyResponse.KeyBytes,
		MacKey: generateMacKeyResponse.KeyBytes,
	}

	// Wrap the AES key
	wrapKeyResponse, err := cryptoClient.WrapKey(context.Background(), wrapKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Wrap AES key error: %s", err))
	}
	fmt.Println("Wrapped AES key")

	aesUnwrapKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:       ep11.CKO_SECRET_KEY,
		ep11.CKA_KEY_TYPE:    ep11.CKK_AES,
		ep11.CKA_VALUE_LEN:   128 / 8,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: true, // must be true to be wrapped
	}
	unwrapRequest := &pb.UnwrapKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_IBM_ATTRIBUTEBOUND_WRAP},
		KeK:      generateKeyPairResponse.PrivKeyBytes,
		MacKey:   generateMacKeyResponse.KeyBytes,
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

// Test_signAndVerifyUsingDilithiumKeyPair generates a Dilithium key pair
// then uses the key pair to sign and verify a sample message
// Flow: connect, generate Dilithium key pair, sign PKCS #11 single-part data, verify PKCS #11 single-part data

// NOTE: Using the Dilithium mechanism is hardware and firmware dependent.  If you receive an error indicating
//       that the CKM_IBM_DILITHIUM mechanism is invalid then the remote HSM currently does not support this mechanism.
func Test_signAndVerifyUsingDilithiumKeyPair(t *testing.T) {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	// Setup PQC parameter and key templates
	dilithiumStrengthParam, err := asn1.Marshal(util.OIDDilithiumHigh)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_IBM_PQC_PARAMS: dilithiumStrengthParam,
		ep11.CKA_VERIFY:         true,
		ep11.CKA_EXTRACTABLE:    false,
	}
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:        true,
		ep11.CKA_EXTRACTABLE: false,
	}
	generateDilKeyPairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_IBM_DILITHIUM},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	// Dilithium Key Pair generation
	generateDilKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateDilKeyPairRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_MECHANISM_INVALID {
			fmt.Println("Dilithium mechanism is not supported on the remote HSM")
			return
		} else {
			panic(fmt.Errorf("Generate Dilithium key pair error: %s", err))
		}
	}

	fmt.Println("Generated Dilithium key pair")

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_IBM_DILITHIUM},
		PrivKey: generateDilKeyPairResponse.PrivKeyBytes,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	signData := sha256.Sum256([]byte("This data needs to be signed"))
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData[:],
	}

	// Sign the data
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}

	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_IBM_DILITHIUM},
		PubKey: generateDilKeyPairResponse.PubKeyBytes,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}

	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      []byte(signData[:]),
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
	fmt.Println("Verified")
}

// Test_rewrapKeyBlob re-encrypts generated key blobs with the new committed wrapping key that is contained within the HSM.
// Keys that have been re-encrypted can only be used (e.g., encrypt, decrypt) after the HSM has been finalized with the new
// committed wrapping key.
// See figure 8 on page 27 and page 37 of https://www.ibm.com/downloads/cas/WXRDPRAN for additional information.
// This test contains two pauses that require the user to type CTRL-c after ensuring that the stated pre-requisite activity
// has been completed.  There needs to be coordination with your HPCS cloud service contact in order to place your HSM into the
// required states.

func Test_rewrapKeyBlob(t *testing.T) {
	message := `
 
Skipping the rewrapKeyBlob test. To enable, comment out the t.Skipf and message lines within the Test_rewrapKeyBlob test

NOTE: This test contains two pauses that require the user to type CTRL-c after ensuring
      that the stated pre-requisite activity has been completed.  There needs to be 
      coordination with your HPCS cloud service contact in order to place your HSM
      into the required states.
 
`
	t.Skipf(message)

	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		t.Fatalf("Could not connect to server: %s", err)
	}
	defer conn.Close()

	// Setup Crypto client
	cryptoClient := pb.NewCryptoClient(conn)
	// Generate AES key blob for testing
	keyLen := 128
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN:   keyLen / 8,
		ep11.CKA_WRAP:        false,
		ep11.CKA_UNWRAP:      false,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: false,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		t.Fatalf("GenerateKey Error: %s", err)
	}

	t.Log("Generated original AES key that will be rewrapped")

	// Encrypt data using the generated AES key blob. The encrypted data will be used later in the test.
	// The data will be decrypted by the re-wrapped AES key blob.
	rngTemplate := &pb.GenerateRandomRequest{
		Len: (uint64)(ep11.AES_BLOCK_SIZE),
	}

	// Generate a 16 byte initialization vector for the encrypt/decrypt operations
	rng, err := cryptoClient.GenerateRandom(context.Background(), rngTemplate)
	if err != nil {
		t.Fatalf("GenerateRandom Error: %s", err)
	}
	iv := rng.Rnd[:ep11.AES_BLOCK_SIZE]
	plain := []byte("This text will be used to confirm a successful key blob re-encrypt operation")

	encryptRequest := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:   generateKeyResponse.KeyBytes,
		Plain: plain,
	}

	// Encrypt the data before performing a RewrapKeyBlob operation
	origEncryptResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptRequest)
	if err != nil {
		t.Fatalf("Failed EncryptSingle [%s]", err)
	}

	t.Log("Encrypted message using the original wrapped AES key")

	// Call RewrapKeyBlob function
	rewrapKeyBlobRequest := &pb.RewrapKeyBlobRequest{
		WrappedKey: generateKeyResponse.KeyBytes,
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	msg := make(chan string, 1)
	go func() {
		for {
			var s string
			fmt.Scan(&s)
			msg <- s
		}
	}()

	// Pause here until user is ready to rewrap key blobs
	util.Pause(msg, sigs, "Press Ctrl-c after the domain has been placed into the committed state in order to continue with the RewrapKeyBlob action")

	// Rewrap the AES key blob using the HSM's new wrapping key
	rewrapKeyBlobResponse, err := cryptoClient.RewrapKeyBlob(context.Background(), rewrapKeyBlobRequest)
	if err != nil {
		t.Fatalf("Received error for RewrapKeyBlob operation: %s", err)
	}

	t.Log("RewrapKeyBlob action has completed")
	t.Log("Original wrapped AES key has been rewrapped with the new wrapping key")

	// Pause here until domain has been finalized
	util.Pause(msg, sigs, "Press Ctrl-c after the card has been finalized in order to continue testing the new wrapped key")

	// Test encrypting same plain text with new key
	encryptRequest = &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:   rewrapKeyBlobResponse.RewrappedKey,
		Plain: plain,
	}

	encryptResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptRequest)
	if err != nil {
		t.Fatalf("Failed EncryptSingle [%s]", err)
	}

	t.Log("Encrypted message using the rewrapped AES key")

	// Decrypt data that was encrypted with the new wrapped AES key
	decryptRequest := &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:      rewrapKeyBlobResponse.RewrappedKey,
		Ciphered: encryptResponse.Ciphered,
	}
	decryptResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptRequest)
	if err != nil {
		t.Fatalf("Failed DecryptSingle using the rewrapped AES key [%s]", err)
	}

	// Compare decrypted response (using the second wrapping key) with the original plain text
	if !reflect.DeepEqual(plain, decryptResponse.Plain) {
		t.Fatalf("Failed comparing plain text of cipher single using the reencrypted AES key")
	}

	t.Log("Successfully decrypted new data with the rewrapped AES key")

	// Decrypt initial data that was encrypted with new wrapping key
	decryptRequest = &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:      rewrapKeyBlobResponse.RewrappedKey,
		Ciphered: origEncryptResponse.Ciphered,
	}
	decryptResponse, err = cryptoClient.DecryptSingle(context.Background(), decryptRequest)
	if err != nil {
		t.Fatalf("Failed DecryptSingle using the rewrapped AES key [%s]", err)
	}

	// Compare decrypted response (using the second wrapping key) with the original plain text
	if !reflect.DeepEqual(plain, decryptResponse.Plain) {
		t.Fatalf("Failed comparing plain text of cipher single using the rewrapped AES key")
	}

	t.Log("Successfully decrypted original data with the rewrapped AES key")
}
