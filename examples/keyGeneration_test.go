/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"encoding/asn1"
	"fmt"
	"testing"

	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/util"
)

// This file contains examples of generating symmetric and asymmetric keys.
// Examples include key generation for:
// Generic keys
// AES keys
// DES3 keys
// RSA key pairs
// Standard Eliptic Curve (EC) key pairs
// BLS12-381 key pairs
// Kyber key pairs
// Diffie-Hellman key pairs
// DSA key pairs

// Example_keygen_GenericKey creates a generic key
// Generic keys can be used to derive new keys
// Flow: connect, generate generic key
func Example_keygen_GenericKey() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	keyLen := 128 // bits
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_KEY_TYPE:    ep11.CKK_GENERIC_SECRET,
		ep11.CKA_CLASS:       ep11.CKO_SECRET_KEY,
		ep11.CKA_VALUE_LEN:   keyLen / 8,
		ep11.CKA_EXTRACTABLE: true, // if key is to be wrapped then set to true, otherwise, remove attribute from the template
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

// Example_keygen_AES generates a 256-bit AES key
// Flow: connect, generate AES key
func Example_keygen_AES() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	keyLen := 256 // 256-bit AES key

	// Setup the AES key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN:   keyLen / 8,
		ep11.CKA_WRAP:        true,
		ep11.CKA_UNWRAP:      true,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: true, // if key is to be wrapped then set to true, otherwise, remove attribute from the template
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

	_ = generateKeyResponse // simulates the use of the key

	fmt.Println("Generated 256-bit AES Key")

	// Output:
	// Generated 256-bit AES Key
}

// Example_keygen_DES3 generates a 256-bit DES3 key
// Flow: connect, generate DES3 key
func Example_keygen_DES3() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	keyLen := 256 // 256-bit DES3 key

	// Setup the DES3 key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN:   keyLen / 8,
		ep11.CKA_WRAP:        true,
		ep11.CKA_UNWRAP:      true,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: true, // if key is to be wrapped then set to true, otherwise, remove attribute from the template
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

	_ = generateKeyResponse // simulates the use of the key

	fmt.Println("Generated 256-bit DES3 Key")

	// Output:
	// Generated 256-bit DES3 Key
}

// Example_keygen_RSA generates a RSA key pair
// Flow: connect, generate RSA key pair
func Example_keygen_RSA() {
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
		ep11.CKA_EXTRACTABLE: true, // if key is to be wrapped then set to true, otherwise, remove attribute from the template
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

	_ = generateKeyPairResponse // simulates the use of the key pair

	fmt.Println("Generated RSA key pair")

	// Output:
	// Generated RSA key pair
}

// Example_keygen_EC generates an EC key pair
// Flow: connect, generate EC key pair
func Example_keygen_EC() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// EC Curve variables that can be for EC key pair generation:
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
		ep11.CKA_SIGN:        true, // allow private key to perform sign operations
		ep11.CKA_PRIVATE:     true,
		ep11.CKA_SENSITIVE:   true,
		ep11.CKA_EXTRACTABLE: true, // if key is to be wrapped then set to true, otherwise, remove attribute from the template
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

	_ = generateKeyPairResponse // simulates the use of the key pair

	fmt.Println("Generated EC key pair")

	// Output:
	// Generated EC key pair
}

// Test_keygen_BLS12 generates a BLS12-381 key pair
// Flow: connect, generate BLS12-381 key pair
func Test_keygen_BLS12(t *testing.T) {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Indirectly check to see if BLS is supported on the remote HSM. BLS is only supported on CEX7 and CEX8 cards.
	// Since the CKM_IBM_DILITHIUM mechanism can only be found on CEX7 or CEX8 cards, a check is made
	// for the existence of the CKM_IBM_DILITHIUM mechanism.  If it exists, it also indicates that BLS
	// support exists for the remote HSM.
	if !util.MechanismExists(cryptoClient, ep11.CKM_IBM_DILITHIUM) {
		t.Skip("BLS is not supported on the remote HSM")
	}

	ecParameters, err := asn1.Marshal(util.OIDBLS12_381ET)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	publicKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_EC_PARAMS: ecParameters,
		ep11.CKA_VERIFY:    true,
	}
	privateKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:      true,
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

	_ = generateKeyPairResponse // simulates the use of the key pair

	fmt.Println("Generated BLS12-381 key pair")

	// Output:
	// Generated BLS12-381 key pair
}

// Test_keygen_Kyber generates a Kyber key pair
// Flow: connect, generate Kyber key pair
func Test_keygen_Kyber(t *testing.T) {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Check to see if the CKM_IBM_KYBER mechanism is supported on the remote HSM
	if !util.MechanismExists(cryptoClient, ep11.CKM_IBM_KYBER) {
		t.Skip("Kyber mechanism (CKM_IBM_KYBER) is not supported on the remote HSM")
	}

	// Currently, there are two strengths of Kyber keys:
	// util.OIDKyberR2Rec  OID 1.3.6.1.4.1.2.267.5.3.3
	// util.OIDKyberR2High OID 1.3.6.1.4.1.2.267.5.4.4

	kyberStrengthParam, err := asn1.Marshal(util.OIDKyberR2High)
	if err != nil {
		panic(fmt.Errorf("Error marshalling Kyber strength: %s", err))
	}

	publicKyberKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:          ep11.CKO_PUBLIC_KEY,
		ep11.CKA_IBM_PQC_PARAMS: kyberStrengthParam,
		ep11.CKA_ENCRYPT:        true,
		ep11.CKA_DERIVE:         true,
	}
	privateKyberKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:   ep11.CKO_PRIVATE_KEY,
		ep11.CKA_DECRYPT: true,
		ep11.CKA_DERIVE:  true,
	}
	kyberKeyPairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_IBM_KYBER},
		PubKeyTemplate:  util.AttributeMap(publicKyberKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKyberKeyTemplate),
	}

	// Kyber key pair generation
	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), kyberKeyPairRequest)
	if err != nil {
		panic(fmt.Errorf("Error occurred when generating a Kyber key pair: %s", err))
	}

	_ = generateKeyPairResponse // simulates the use of the key pair

	fmt.Println("Generated Kyber key pair")

	// Output:
	// Generated Kyber key pair
}

// Example_keygen_Diffie_Hellman generates a Diffie-Hellman (DH) key pair
// Flow: connect, generate DH domain parameters, generate DH key pair using domain parameters
func Example_keygen_Diffie_Hellman() {
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

	// Create Diffie-Hellman domain parameters for Alice and Bob
	commonGenerateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated Diffie-Hellman domain parameters for Alice and Bob")

	commonPublicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_DERIVE:            true,
		ep11.CKA_IBM_STRUCT_PARAMS: commonGenerateKeyResponse.KeyBytes,
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_DERIVE:    true,
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
	}

	// Now generate the Diffie-Hellman key pair for Alice using Alice's domain parameters created in the previous step
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_DH_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(commonPublicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	_ = generateKeyPairResponse // simulates the use of the key pair

	fmt.Println("Generated Diffie-Hellman key pair for Alice")

	// Output:
	// Generated Diffie-Hellman domain parameters for Alice and Bob
	// Generated Diffie-Hellman key pair for Alice
}

// Example_keygen_DSA generates a DSA key pair
// Flow: connect, generate DSA domain parameters, generate DSA key pair using domain parameters
func Example_keygen_DSA() {
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

	// Create DSA domain parameters
	domainParms, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey error: %s", err))
	}

	fmt.Println("Generated DSA domain parameters")

	commonPublicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VERIFY:            true,
		ep11.CKA_IBM_STRUCT_PARAMS: domainParms.Key.KeyBlobs[0],
	}

	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:      true,
		ep11.CKA_PRIVATE:   true,
		ep11.CKA_SENSITIVE: true,
	}

	// Now generate the DSA key pair
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_DSA_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(commonPublicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	_ = generateKeyPairResponse // simulates the use of the key pair

	fmt.Println("Generated DSA key pair")

	// Output:
	// Generated DSA domain parameters
	// Generated DSA key pair
}
