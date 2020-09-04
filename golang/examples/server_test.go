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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"testing"

	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/util"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// The following IBM Cloud items need to be changed prior to running the sample program
const address = "<grep11_server_address>:<port>"

var skip bool

var callOpts = []grpc.DialOption{
	grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
	grpc.WithPerRPCCredentials(&util.IAMPerRPCCredentials{
		APIKey:   "<ibm_cloud_apikey>",
		Endpoint: "<https://<iam_ibm_cloud_endpoint>",
		Instance: "<hpcs_instance_id>",
	}),
}

func TestMain(m *testing.M) {
	flag.BoolVar(&skip, "skip", true, "skip rewrapKeyBlob test")
	flag.Parse()

	m.Run()
}

// Example_getMechanismInfo retrieves a mechanism list and retrieves detailed information for the CKM_RSA_PKCS mechanism
// Flow: connect, get mechanism list, get mechanism info
func Example_getMechanismInfo() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	mechanismListRequest := &pb.GetMechanismListRequest{}
	mechanismListResponse, err := cryptoClient.GetMechanismList(context.Background(), mechanismListRequest)
	if err != nil {
		panic(fmt.Errorf("Get mechanism list error: %s", err))
	}
	fmt.Printf("Got mechanism list:\n%v ...\n", mechanismListResponse.Mechs[:1])

	mechanismInfoRequest := &pb.GetMechanismInfoRequest{
		Mech: ep11.CKM_RSA_PKCS,
	}
	_, err = cryptoClient.GetMechanismInfo(context.Background(), mechanismInfoRequest)
	if err != nil {
		panic(fmt.Errorf("Get mechanism info error: %s", err))
	}

	// Output:
	// Got mechanism list:
	// [CKM_RSA_PKCS] ...
}

// Example_encryptAndDecrypt encrypts and decrypts plain text
// Flow: connect, generate AES key, generate IV, encrypt multi-part data, decrypt multi-part data
func Example_encryptAndDecrypt() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)
	keyLen := 128
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN:   keyLen / 8,
		ep11.CKA_WRAP:        false,
		ep11.CKA_UNWRAP:      false,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: false, // set to false!
		ep11.CKA_TOKEN:       true,  // ignored by EP11
	}

	keyGenMsg := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	generateKeyStatus, err := cryptoClient.GenerateKey(context.Background(), keyGenMsg)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated AES Key")

	rngTemplate := &pb.GenerateRandomRequest{
		Len: (uint64)(ep11.AES_BLOCK_SIZE),
	}
	rng, err := cryptoClient.GenerateRandom(context.Background(), rngTemplate)
	if err != nil {
		panic(fmt.Errorf("GenerateRandom Error: %s", err))
	}
	iv := rng.Rnd[:ep11.AES_BLOCK_SIZE]
	fmt.Println("Generated IV")

	encipherInitInfo := &pb.EncryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: &pb.Mechanism_ParameterB{ParameterB: iv}},
		Key:  generateKeyStatus.KeyBytes, // you may want to store this
	}
	cipherStateInit, err := cryptoClient.EncryptInit(context.Background(), encipherInitInfo)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptInit [%s]", err))
	}

	plain := []byte("Hello, this is a very long and creative message without any imagination")

	encipherDataUpdate := &pb.EncryptUpdateRequest{
		State: cipherStateInit.State,
		Plain: plain[:20],
	}
	encipherStateUpdate, err := cryptoClient.EncryptUpdate(context.Background(), encipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed Encrypt [%s]", err))
	}

	ciphertext := encipherStateUpdate.Ciphered[:]
	encipherDataUpdate = &pb.EncryptUpdateRequest{
		State: encipherStateUpdate.State,
		Plain: plain[20:],
	}
	encipherStateUpdate, err = cryptoClient.EncryptUpdate(context.Background(), encipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed Encrypt [%s]", err))
	}

	ciphertext = append(ciphertext, encipherStateUpdate.Ciphered...)
	encipherDataFinal := &pb.EncryptFinalRequest{
		State: encipherStateUpdate.State,
	}
	encipherStateFinal, err := cryptoClient.EncryptFinal(context.Background(), encipherDataFinal)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptFinal [%s]", err))
	}

	ciphertext = append(ciphertext, encipherStateFinal.Ciphered...)
	fmt.Println("Encrypted message")

	decipherInitInfo := &pb.DecryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: &pb.Mechanism_ParameterB{ParameterB: iv}},
		Key:  generateKeyStatus.KeyBytes, // you may want to store this
	}
	decipherStateInit, err := cryptoClient.DecryptInit(context.Background(), decipherInitInfo)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptInit [%s]", err))
	}

	decipherDataUpdate := &pb.DecryptUpdateRequest{
		State:    decipherStateInit.State,
		Ciphered: ciphertext[:16],
	}
	decipherStateUpdate, err := cryptoClient.DecryptUpdate(context.Background(), decipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptUpdate [%s]", err))
	}

	plaintext := decipherStateUpdate.Plain[:]
	decipherDataUpdate = &pb.DecryptUpdateRequest{
		State:    decipherStateUpdate.State,
		Ciphered: ciphertext[16:],
	}
	decipherStateUpdate, err = cryptoClient.DecryptUpdate(context.Background(), decipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptUpdate [%s]", err))
	}
	plaintext = append(plaintext, decipherStateUpdate.Plain...)

	decipherDataFinal := &pb.DecryptFinalRequest{
		State: decipherStateUpdate.State,
	}
	decipherStateFinal, err := cryptoClient.DecryptFinal(context.Background(), decipherDataFinal)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptFinal [%s]", err))
	}
	plaintext = append(plaintext, decipherStateFinal.Plain...)

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing plain text of cipher single"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)

	// Output:
	// Generated AES Key
	// Generated IV
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message without any imagination
}

// Example_digest calculates the digest of some plain text
// Flow: connect, digest single-part data, digest multi-part data
func Example_digest() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	digestData := []byte("This is the data longer than 64 bytes This is the data longer than 64 bytes")
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
		panic(fmt.Errorf("Digest init error: %s", err))
	}
	digestUpdateRequest := &pb.DigestUpdateRequest{
		State: digestInitResponse.State,
		Data:  digestData[:64],
	}
	digestUpdateResponse, err := cryptoClient.DigestUpdate(context.Background(), digestUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("Digest update error: %s", err))
	}
	digestUpdateRequest = &pb.DigestUpdateRequest{
		State: digestUpdateResponse.State,
		Data:  digestData[64:],
	}
	digestUpdateResponse, err = cryptoClient.DigestUpdate(context.Background(), digestUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("Digest update error: %s", err))
	}
	digestFinalRequestInfo := &pb.DigestFinalRequest{
		State: digestUpdateResponse.State,
	}
	digestFinalResponse, err := cryptoClient.DigestFinal(context.Background(), digestFinalRequestInfo)
	if err != nil {
		panic(fmt.Errorf("Digest final error: %s", err))
	} else {
		fmt.Printf("Digest data using multiple operations: %x\n", digestFinalResponse.Digest)
	}

	// Output:
	// Digest data using a single digest operation: ad4e0b6e309d192862ec6db692d17072ddd3a98ccd37afe642a04f7ca554c94c
	// Digest data using multiple operations: ad4e0b6e309d192862ec6db692d17072ddd3a98ccd37afe642a04f7ca554c94c
}

// Example_signAndVerifyUsingRSAKeyPair signs some data and verifies it
// Flow: connect, generate RSA key pair, sign single-part data, verify single-part data
func Example_signAndVerifyUsingRSAKeyPair() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	// Generate RSA key pairs
	publicExponent := []byte{0x11}
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
	generateKeyPairStatus, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}
	fmt.Println("Generated RSA PKCS key pair")

	// Sign data
	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_SHA1_RSA_PKCS},
		PrivKey: generateKeyPairStatus.PrivKeyBytes,
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
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}
	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_SHA1_RSA_PKCS},
		PubKey: generateKeyPairStatus.PubKeyBytes,
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

// Example_signAndVerifyUsingECDSAKeyPair generates an ECDSA key pair and uses the key pair to sign and verify data
// Flow: connect, generate ECDSA key pair, sign single-part data, verify single-part data
func Example_signAndVerifyUsingECDSAKeyPair() {
	conn, err := grpc.Dial(address, callOpts...)
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
	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyECTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyECTemplate),
	}
	generateKeyPairStatus, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated ECDSA PKCS key pair")

	// Sign data
	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: generateKeyPairStatus.PrivKeyBytes,
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
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}
	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey: generateKeyPairStatus.PubKeyBytes,
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
// Flow: connect, generate ECDSA key pair, sign single-part data, modify signature to force verify error,
//                verify single-part data, ensure proper error is returned
func Example_signAndVerifyToTestErrorHandling() {
	conn, err := grpc.Dial(address, callOpts...)
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
	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyECTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyECTemplate),
	}
	generateKeyPairStatus, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated ECDSA PKCS key pair")

	// Sign data
	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: generateKeyPairStatus.PrivKeyBytes,
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
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}
	fmt.Println("Data signed")

	// Modify signature to force returned error code
	SignResponse.Signature[0] = 255

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey: generateKeyPairStatus.PubKeyBytes,
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
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)

	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Printf("Invalid signature\n")
			return
		}
		panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
	}

	// Output:
	// Generated ECDSA PKCS key pair
	// Data signed
	// Invalid signature
}

// Example_wrapAndUnWrapKey wraps an AES key with a RSA public key and then unwraps it with the private key
// Flow: connect, generate AES key, generate RSA key pair, wrap/unwrap AES key with RSA key pair
func Example_wrapAndUnwrapKey() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	// Generate a AES key
	desKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN:   128 / 8,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: true, // must be true to be wrapped
	}
	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(desKeyTemplate),
	}
	generateNewKeyStatus, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generate AES key error: %s", err))
	} else {
		fmt.Println("Generated AES key")
	}

	// Generate RSA key pairs
	publicExponent := []byte{0x11}
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
	generateKeyPairStatus, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}
	fmt.Println("Generated PKCS key pair")

	wrapKeyRequest := &pb.WrapKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		KeK:  generateKeyPairStatus.PubKeyBytes,
		Key:  generateNewKeyStatus.KeyBytes,
	}
	wrapKeyResponse, err := cryptoClient.WrapKey(context.Background(), wrapKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Wrap AES key error: %s", err))
	}
	fmt.Println("Wrapped AES key")

	desUnwrapKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:       ep11.CKO_SECRET_KEY,
		ep11.CKA_KEY_TYPE:    ep11.CKK_AES,
		ep11.CKA_VALUE_LEN:   128 / 8,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: true, // must be true to be wrapped
	}
	unwrapRequest := &pb.UnwrapKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		KeK:      generateKeyPairStatus.PrivKeyBytes,
		Wrapped:  wrapKeyResponse.Wrapped,
		Template: util.AttributeMap(desUnwrapKeyTemplate),
	}
	unWrappedResponse, err := cryptoClient.UnwrapKey(context.Background(), unwrapRequest)
	if err != nil {
		panic(fmt.Errorf("Unwrap AES key error: %s", err))
	}
	if !bytes.Equal(generateNewKeyStatus.GetCheckSum()[:3], unWrappedResponse.GetCheckSum()[:3]) {
		panic(fmt.Errorf("Unwrap AES key has a different checksum than the original key"))
	} else {
		fmt.Println("Unwrapped AES key")
	}

	// Output:
	// Generated AES key
	// Generated PKCS key pair
	// Wrapped AES key
	// Unwrapped AES key
}

// Example_deriveKey generates ECDHE key pairs for Bob and Alice and then generates AES keys for both of them.
// The names Alice and Bob are described in https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange.
// Flow: connect, generate key pairs, derive AES key for Bob, derive AES key for Alice, encrypt with Alice's AES key and decrypt with Bob's AES key
func Example_deriveKey() {
	conn, err := grpc.Dial(address, callOpts...)
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

	publicKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_EC_PARAMS:   ecParameters,
		ep11.CKA_EXTRACTABLE: false,
	}
	privateKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_DERIVE:      true,
		ep11.CKA_EXTRACTABLE: false,
	}
	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyECTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyECTemplate),
	}
	aliceECKeypairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("Generate Alice EC key pair error: %s", err))
	}
	fmt.Println("Generated Alice EC key pair")

	bobECKeypairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("Generate Bob EC key pair error: %s", err))
	}
	fmt.Println("Generated Bob EC key pair")

	// Derive AES key for Alice
	deriveKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:     ep11.CKO_SECRET_KEY,
		ep11.CKA_KEY_TYPE:  ep11.CKK_AES,
		ep11.CKA_VALUE_LEN: 128 / 8,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}
	combinedCoordinates, err := util.GetPubkeyBytesFromSPKI(bobECKeypairResponse.PubKeyBytes)
	if err != nil {
		panic(fmt.Errorf("Bob's EC key cannot obtain coordinates: %s", err))
	}
	aliceDerivekeyRequest := &pb.DeriveKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_ECDH1_DERIVE, Parameter: &pb.Mechanism_ParameterB{ParameterB: combinedCoordinates}},
		Template: util.AttributeMap(deriveKeyTemplate),
		BaseKey:  aliceECKeypairResponse.PrivKeyBytes,
	}
	aliceDerivekeyResponse, err := cryptoClient.DeriveKey(context.Background(), aliceDerivekeyRequest)
	if err != nil {
		panic(fmt.Errorf("Alice EC key derive error: %s", err))
	}

	// Derive AES key for Bob
	combinedCoordinates, err = util.GetPubkeyBytesFromSPKI(aliceECKeypairResponse.PubKeyBytes)
	if err != nil {
		panic(fmt.Errorf("Alice's EC key cannot obtain coordinates: %s", err))
	}
	bobDerivekeyRequest := &pb.DeriveKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_ECDH1_DERIVE, Parameter: &pb.Mechanism_ParameterB{ParameterB: combinedCoordinates}},
		Template: util.AttributeMap(deriveKeyTemplate),
		BaseKey:  bobECKeypairResponse.PrivKeyBytes,
	}
	bobDerivekeyResponse, err := cryptoClient.DeriveKey(context.Background(), bobDerivekeyRequest)
	if err != nil {
		panic(fmt.Errorf("Bob EC Key Derive Error: %s", err))
	}

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
		Key:   aliceDerivekeyResponse.NewKeyBytes,
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: &pb.Mechanism_ParameterB{ParameterB: iv}},
		Plain: msg,
	}
	encryptResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptRequest)
	if err != nil {
		panic(fmt.Errorf("Encrypt error: %s", err))
	}

	decryptRequest := &pb.DecryptSingleRequest{
		Key:      bobDerivekeyResponse.NewKeyBytes,
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: &pb.Mechanism_ParameterB{ParameterB: iv}},
		Ciphered: encryptResponse.Ciphered,
	}
	decryptResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptRequest)
	if err != nil {
		panic(fmt.Errorf("Decrypt error: %s", err))
	}

	if !bytes.Equal(decryptResponse.Plain, msg) {
		panic(fmt.Errorf("Decrypted message[%v] is different from the original message: [%v]", decryptResponse.Plain, msg))
	} else {
		fmt.Println("Alice and Bob get the same derived key")
	}

	return

	// Output:
	// Generated Alice EC key pair
	// Generated Bob EC key pair
	// Alice and Bob get the same derived key
}

// Example_rewrapKeyBlob re-encrypts generated key blobs with the new committed wrapping key that is contained within with the HSM.
// Keys that have been re-encrypted can only be used (e.g., encrypt, decrypt) after the HSM has been finalized with the new
// committed wrapping key.
// See figure 8 on page 27 and page 37 of https://www.ibm.com/downloads/cas/WXRDPRAN for additional information.
// This example contains two pauses that require the user to type CTRL-c after ensuring that the stated pre-requisite activity
// has been completed.  There needs to be coordination with your HPCS cloud service contact in order to place your HSM into the
// required states.

func Example_rewrapKeyBlob() {
	if skip {
		fmt.Printf("Skipping the rewrapKeyBlob test. To enable, use the go test parameter \"-skip=false\"\n")
		return
	}

	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
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
		ep11.CKA_TOKEN:       true,
	}

	keygenmsg := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), keygenmsg)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}

	fmt.Println("Generated original AES key that will be rewrapped")

	// Encrypt data using generated AES key blob. The encrypted data will be used later in the test
	// The data will be decrypted by the re-wrapped AES key blob.
	rngTemplate := &pb.GenerateRandomRequest{
		Len: (uint64)(ep11.AES_BLOCK_SIZE),
	}
	rng, err := cryptoClient.GenerateRandom(context.Background(), rngTemplate)
	if err != nil {
		panic(fmt.Errorf("GenerateRandom Error: %s", err))
	}
	iv := rng.Rnd[:ep11.AES_BLOCK_SIZE]
	plain := []byte("This text will be used to confirm a successful key blob re-encrypt operation")

	encryptRequest := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: &pb.Mechanism_ParameterB{ParameterB: iv}},
		Key:   generateKeyResponse.KeyBytes,
		Plain: plain,
	}

	origEncryptResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptRequest)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptSingle [%s]", err))
	}

	fmt.Println("Encrypted message using original wrapped AES key")

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

	rewrapKeyBlobResponse, err := cryptoClient.RewrapKeyBlob(context.Background(), rewrapKeyBlobRequest)
	if err != nil {
		panic(fmt.Errorf("Received error for RewrapKeyBlob operation: %s", err))
	}

	fmt.Println("RewrapKeyBlob action has completed")
	fmt.Println("Original wrapped AES key has been rewrapped with the new wrapping key")

	// Pause here until domain has been finalized
	util.Pause(msg, sigs, "Press Ctrl-c after the card has been finalized in order to continue testing the new wrapped key")

	// Test encrypting same plain text with new key
	encryptRequest = &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: &pb.Mechanism_ParameterB{ParameterB: iv}},
		Key:   rewrapKeyBlobResponse.RewrappedKey,
		Plain: plain,
	}

	encryptResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptRequest)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptSingle [%s]", err))
	}

	fmt.Println("Encrypted message using rewrapped AES key")

	// Decrypt data that was encrypted with the new wrapped AES key
	decryptRequest := &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: &pb.Mechanism_ParameterB{ParameterB: iv}},
		Key:      rewrapKeyBlobResponse.RewrappedKey,
		Ciphered: encryptResponse.Ciphered,
	}
	decryptResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptRequest)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptSingle using rewrapped AES key [%s]", err))
	}

	// Compare decrypted response (using the second wrapping key) with the original plain text
	if !reflect.DeepEqual(plain, decryptResponse.Plain) {
		panic(fmt.Errorf("Failed comparing plain text of cipher single using reencrypted AES key"))
	}

	fmt.Println("Successfully decrypted new data with rewrapped AES key")

	// Decrypt initial data that was encrypted with new wrapping key
	decryptRequest = &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: &pb.Mechanism_ParameterB{ParameterB: iv}},
		Key:      rewrapKeyBlobResponse.RewrappedKey,
		Ciphered: origEncryptResponse.Ciphered,
	}
	decryptResponse, err = cryptoClient.DecryptSingle(context.Background(), decryptRequest)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptSingle using rewrapped AES key [%s]", err))
	}

	// Compare decrypted response (using the second wrapping key) with the original plain text
	if !reflect.DeepEqual(plain, decryptResponse.Plain) {
		panic(fmt.Errorf("Failed comparing plain text of cipher single using rewrapped AES key"))
	}

	fmt.Println("Successfully decrypted original data with rewrapped AES key")

	return

	// Output:
	// Generated original AES key that will be rewrapped
	// Encrypted message using original wrapped AES key
	//
	// RewrapKeyBlob action has completed
	// Original wrapped AES key has been rewrapped with the new wrapping key
	//
	// Encrypted message using rewrapped AES key
	// Successfully decrypted new data with rewrapped AES key
	// Successfully decrypted original data with rewrapped AES key
}
