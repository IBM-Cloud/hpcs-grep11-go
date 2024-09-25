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

// Test_bls12_GenerateKeyPair generates a BLS key pair using the BLS12_381ET OID
// Flow: connect, generate BLS key pair
func Test_bls12_GenerateKeyPair(t *testing.T) {
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
	_, err = cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated BLS12-381 key pair")

	// Output:
	// Generated BLS12-381 key pair
}

// Test_bls12_SignSingleVerifySingle generates a BLS key pair and
// performs SignSingle and VerifySingle operations on some sample data
// Flow: connect, generate BLS key pair, sign sample data using the BLS
// private key, verify the signature using the BLS public key
func Test_bls12_SignSingleVerifySingle(t *testing.T) {
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

	fmt.Println("Generated BLS12-381 key pair")

	msg := []byte("Test message for sign and verify operations")

	signMsg := &pb.SignSingleRequest{
		PrivKey: generateKeyPairResponse.PrivKey,
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_ECDSA_OTHER,
			Parameter: &pb.Mechanism_ECSGParameter{
				ECSGParameter: &pb.ECSGParm{
					Type: pb.ECSGParm_CkEcsgIbmBls,
				},
			},
		},
		Data: msg,
	}

	fmt.Println("Performing BLS12-381 SignSingle operation")
	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signMsg)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	fmt.Println("SignSingle operation completed without error")

	// Verify the signature with the public key
	verifySingleRequest := &pb.VerifySingleRequest{
		PubKey: generateKeyPairResponse.PubKey,
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_ECDSA_OTHER,
			Parameter: &pb.Mechanism_ECSGParameter{
				ECSGParameter: &pb.ECSGParm{
					Type: pb.ECSGParm_CkEcsgIbmBls,
				},
			},
		},
		Data:      msg,
		Signature: signSingleResponse.Signature,
	}

	fmt.Println("Performing BLS12-381 VerifySingle operation")
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if err != nil {
		panic(fmt.Errorf("VerifySingle error: %s", err))
	}

	fmt.Println("VerifySingle operation completed without error")

	// Output:
	// Generated BLS12-381 key pair
	// SignSingle operation completed without error
	// VerifySingle operation completed without error
}

// Test_bls12_Aggregation flow:
// 1. Generate 10 BLS12-381 key pairs and save all private and public keys
// 2. Perform a sign and verify operation using each of the 10 key pairs and save all signatures
// 3. Perform a special SignSingle (no key used) operation to create an aggregated signature from the saved signatures
// 4. Create an aggregated public key from all saved public keys using a DeriveKey operation
// 5. Verify the aggregated signature using the derived aggregated public key
// 6. Verify the aggregated signature using a concatenation of all saved public keys
func Test_bls12_Aggregation(t *testing.T) {
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

	// Setup key pair request
	publicKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_EC_PARAMS:       ecParameters,
		ep11.CKA_VERIFY:          true,
		ep11.CKA_DERIVE:          true,
		ep11.CKA_IBM_USE_AS_DATA: true,
		ep11.CKA_KEY_TYPE:        ep11.CKK_EC,
	}
	privateKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:            true,
		ep11.CKA_IBM_USE_AS_DATA: true,
		ep11.CKA_KEY_TYPE:        ep11.CKK_EC,
	}
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyECTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyECTemplate),
	}

	// Generate 10 BLS key pairs and perform a sign and verify operation using each of the 10 key pairs.
	// Key pair and signature information is used in the aggregation steps below.
	const maxKeyPairs = 10
	msg := []byte("Test message for aggregation operations")
	signatures := make([][]byte, 10)
	keyPairs := make([]*pb.GenerateKeyPairResponse, 10)

	for i := 0; i < maxKeyPairs; i++ {
		keyPairs[i], err = cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
		if err != nil {
			panic(fmt.Errorf("GenerateKeyPair error: %s", err))
		}

		signSingleRequest := &pb.SignSingleRequest{
			PrivKey: keyPairs[i].PrivKey,
			Mech: &pb.Mechanism{
				Mechanism: ep11.CKM_IBM_ECDSA_OTHER,
				Parameter: &pb.Mechanism_ECSGParameter{
					ECSGParameter: &pb.ECSGParm{
						Type: pb.ECSGParm_CkEcsgIbmBls,
					},
				},
			},
			Data: msg,
		}

		signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
		if err != nil {
			panic(fmt.Errorf("SignSingle error: %s", err))
		}

		// Save signature for aggregation operations below
		signatures[i] = signSingleResponse.Signature

		verifySingleRequest := &pb.VerifySingleRequest{
			PubKey: keyPairs[i].PubKey,
			Mech: &pb.Mechanism{
				Mechanism: ep11.CKM_IBM_ECDSA_OTHER,
				Parameter: &pb.Mechanism_ECSGParameter{
					ECSGParameter: &pb.ECSGParm{
						Type: pb.ECSGParm_CkEcsgIbmBls,
					},
				},
			},
			Data:      msg,
			Signature: signatures[i],
		}

		// Confirm that individual signatures can be verified
		_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
		if err != nil {
			panic(fmt.Errorf("VerifySingle error: %s", err))
		}
	}

	fmt.Println("Generated BLS12-381 key pairs and used each key pair for SignSingle and VerifySingle operations")

	// Perform a SignSingle operation that uses all 10 signatures generated above.  All of the signatures are
	// aggregated together into one signature.
	allSigs := make([]byte, 0)
	elementSize := len(signatures[0]) // Each signature is the same size, so just reference the first signature

	// Consolidate all 10 signatures into a single byte slice
	for _, sig := range signatures {
		allSigs = append(allSigs, sig...)
	}

	// Create an aggregated signature
	// NOTE: No key is involved in this operation
	signSingleRequest := &pb.SignSingleRequest{
		PrivKey: nil,
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_EC_AGGREGATE,
			Parameter: &pb.Mechanism_ECAGGParameter{
				ECAGGParameter: &pb.ECAGGParm{
					Version:        0,
					Mode:           pb.ECAGGParm_CkIbmEcAggBLS12_381Sign,
					PerElementSize: uint32(elementSize),
					Elements:       allSigs,
				},
			},
		},
		Data: msg,
	}

	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("Aggregated BLS SignSingle error: %s", err))
	}

	fmt.Println("Successfully created an aggregated signature from ten individual signatures")

	// Create an aggregated public key using the 10 public keys created earlier
	allPubKeys := make([]byte, 0)
	pubKeyElementSize := len(keyPairs[0].PubKey.KeyBlobs[0]) // All public keys are the same size, so use the first public key's size

	// Consolidate all 10 public key into a single byte slice
	for _, keyPair := range keyPairs {
		allPubKeys = append(allPubKeys, keyPair.PubKey.KeyBlobs[0]...)
	}

	// Create an aggregated public key using DeriveKey
	deriveKeyRequest := &pb.DeriveKeyRequest{
		BaseKey: nil,
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_EC_AGGREGATE,
			Parameter: &pb.Mechanism_ECAGGParameter{
				ECAGGParameter: &pb.ECAGGParm{
					Version:        0,
					Mode:           pb.ECAGGParm_CkIbmEcAggBLS12_381Pkey,
					PerElementSize: uint32(pubKeyElementSize),
					Elements:       allPubKeys,
				},
			},
		},
		Template: util.AttributeMap(publicKeyECTemplate),
	}

	deriveKeyResponse, err := cryptoClient.DeriveKey(context.Background(), deriveKeyRequest)
	if err != nil {
		panic(fmt.Errorf("DeriveKey error: %s", err))
	}

	fmt.Println("Successfully created an aggregated public key from ten individual public keys")

	// Verify the aggregated signature with the aggregated public key
	verifySingleRequest := &pb.VerifySingleRequest{
		PubKey: deriveKeyResponse.NewKey,
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_ECDSA_OTHER,
			Parameter: &pb.Mechanism_ECSGParameter{
				ECSGParameter: &pb.ECSGParm{
					Type: pb.ECSGParm_CkEcsgIbmBls,
				},
			},
		},
		Data:      msg,
		Signature: signSingleResponse.Signature,
	}

	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if err != nil {
		panic(fmt.Errorf("Aggregated BLS SignSingle error: %s", err))
	}

	fmt.Println("Successfully verified the aggregated signature with the aggregated public key")

	// Verify the aggregated signature with all of the public keys
	// In this scenario all of the key blobs need to be consolidated into a single key blob
	// The first key pair generated is used to perform the key blob consolidation (keyPairs[0])
	for i := 1; i < maxKeyPairs; i++ {
		keyPairs[0].PubKey.KeyBlobs[0] = append(keyPairs[0].PubKey.KeyBlobs[0], keyPairs[i].PubKey.KeyBlobs[0]...)
	}

	verifySingleRequest = &pb.VerifySingleRequest{
		PubKey: keyPairs[0].PubKey,
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_ECDSA_OTHER,
			Parameter: &pb.Mechanism_ECSGParameter{
				ECSGParameter: &pb.ECSGParm{
					Type: pb.ECSGParm_CkEcsgIbmBls,
				},
			},
		},
		Data:      msg,
		Signature: signSingleResponse.Signature,
	}

	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if err != nil {
		panic(fmt.Errorf("Aggregated BLS VerifySingle error: %s", err))
	}

	fmt.Println("Successfully verified the aggregated signature using a concatenation of ten public keys")

	// Output:
	// Generated BLS12-381 key pairs and used each key pair for SignSingle and VerifySingle operations
	// Successfully created an aggregated signature from ten individual signatures
	// Successfully created an aggregated public key from ten individual public keys
	// Successfully verified the aggregated signature with the aggregated public key
	// Successfully verified the aggregated signature using a concatenation of ten public keys
}

// Test_bls12_AggregationWithVerificationFailure flow:
// 1. Generate 3 BLS12-381 key pairs and save all private and public keys
// 2. Perform a sign and verify operation using only two key pairs and save all signatures
// 3. Perform a special SignSingle (no key used) operation to create an aggregated signature from the saved signatures
// 4. Create an aggregated public key from all saved public keys using a DeriveKey operation
// 5. Verify the aggregated signature using the derived aggregated public key -- CKR_SIGNATURE_INVALID occurs
// 6. Verify the aggregated signature using a concatenation of all saved public keys -- CKR_SIGNATURE_INVALID occurs
//
// This example demonstrates how a key pair not involved with the aggregated
// signing process results in a verification failure.
func Test_bls12_AggregationWithVerificationFailure(t *testing.T) {
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

	// Setup key pair request
	publicKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_EC_PARAMS:       ecParameters,
		ep11.CKA_VERIFY:          true,
		ep11.CKA_DERIVE:          true,
		ep11.CKA_IBM_USE_AS_DATA: true,
		ep11.CKA_KEY_TYPE:        ep11.CKK_EC,
	}
	privateKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:            true,
		ep11.CKA_DERIVE:          true,
		ep11.CKA_IBM_USE_AS_DATA: true,
		ep11.CKA_KEY_TYPE:        ep11.CKK_EC,
	}
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyECTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyECTemplate),
	}

	// Generate 3 BLS key pairs and perform a sign operation (using only two key private keys)
	// and verify operation using all three public keys.
	// Key pair and signature information is used in the aggregation steps below.
	const maxKeyPairs = 3
	msg := []byte("Test message for aggregation operations")
	signatures := make([][]byte, 2)
	keyPairs := make([]*pb.GenerateKeyPairResponse, 3)

	for i := 0; i < maxKeyPairs; i++ {
		keyPairs[i], err = cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
		if err != nil {
			panic(fmt.Errorf("GenerateKeyPair error: %s", err))
		}

		// Only create signatures using two keys.  The third key is used to prove
		// that aggregated verification fails, since the third key was not involved
		// in the signing process.
		if i < 2 {
			signSingleRequest := &pb.SignSingleRequest{
				PrivKey: keyPairs[i].PrivKey,
				Mech: &pb.Mechanism{
					Mechanism: ep11.CKM_IBM_ECDSA_OTHER,
					Parameter: &pb.Mechanism_ECSGParameter{
						ECSGParameter: &pb.ECSGParm{
							Type: pb.ECSGParm_CkEcsgIbmBls,
						},
					},
				},
				Data: msg,
			}

			signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
			if err != nil {
				panic(fmt.Errorf("SignSingle error: %s", err))
			}

			// Save signature for aggregation operations below
			signatures[i] = signSingleResponse.Signature

			verifySingleRequest := &pb.VerifySingleRequest{
				PubKey: keyPairs[i].PubKey,
				Mech: &pb.Mechanism{
					Mechanism: ep11.CKM_IBM_ECDSA_OTHER,
					Parameter: &pb.Mechanism_ECSGParameter{
						ECSGParameter: &pb.ECSGParm{
							Type: pb.ECSGParm_CkEcsgIbmBls,
						},
					},
				},
				Data:      msg,
				Signature: signatures[i],
			}

			// Confirm that individual signatures can be verified
			_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
			if err != nil {
				panic(fmt.Errorf("VerifySingle error: %s", err))
			}
		}
	}

	fmt.Println("Generated BLS12-381 key pairs")

	// Perform a SignSingle operation that uses the two signatures generated above.
	// The two signatures are aggregated together into one signature.
	allSigs := make([]byte, 0)
	elementSize := len(signatures[0]) // Each signature is the same size, so just reference the first signature

	// Consolidate two signatures into a single byte slice
	for _, sig := range signatures {
		allSigs = append(allSigs, sig...)
	}

	// Create an aggregated signature
	// NOTE: No key is involved in this operation
	signSingleRequest := &pb.SignSingleRequest{
		PrivKey: nil,
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_EC_AGGREGATE,
			Parameter: &pb.Mechanism_ECAGGParameter{
				ECAGGParameter: &pb.ECAGGParm{
					Version:        0,
					Mode:           pb.ECAGGParm_CkIbmEcAggBLS12_381Sign,
					PerElementSize: uint32(elementSize),
					Elements:       allSigs,
				},
			},
		},
		Data: msg,
	}

	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("Aggregated BLS SignSingle error: %s", err))
	}

	fmt.Println("Successfully created an aggregated signature from ten individual signatures")

	// Create an aggregated public key using the two public keys created earlier with an
	// additional public key from a key pair that was not involved in the signing process
	allPubKeys := make([]byte, 0)
	pubKeyElementSize := len(keyPairs[0].PubKey.KeyBlobs[0]) // All public keys are the same size, so use the first public key's size

	// Consolidate all public key into a single byte slice
	for _, keyPair := range keyPairs {
		allPubKeys = append(allPubKeys, keyPair.PubKey.KeyBlobs[0]...)
	}

	// Create an aggregated public key using DeriveKey
	deriveKeyRequest := &pb.DeriveKeyRequest{
		BaseKey: nil,
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_EC_AGGREGATE,
			Parameter: &pb.Mechanism_ECAGGParameter{
				ECAGGParameter: &pb.ECAGGParm{
					Version:        0,
					Mode:           pb.ECAGGParm_CkIbmEcAggBLS12_381Pkey,
					PerElementSize: uint32(pubKeyElementSize),
					Elements:       allPubKeys,
				},
			},
		},
		Template: util.AttributeMap(publicKeyECTemplate),
	}

	deriveKeyResponse, err := cryptoClient.DeriveKey(context.Background(), deriveKeyRequest)
	if err != nil {
		panic(fmt.Errorf("DeriveKey error: %s", err))
	}

	fmt.Println("Successfully created an aggregated public key from three individual public keys")

	// Verify the aggregated signature with the aggregated public key
	verifySingleRequest := &pb.VerifySingleRequest{
		PubKey: deriveKeyResponse.NewKey,
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_ECDSA_OTHER,
			Parameter: &pb.Mechanism_ECSGParameter{
				ECSGParameter: &pb.ECSGParm{
					Type: pb.ECSGParm_CkEcsgIbmBls,
				},
			},
		},
		Data:      msg,
		Signature: signSingleResponse.Signature,
	}

	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Println("Expected invalid signature error occurred")
		} else {
			panic("Invalid signature error was expected, but did not occur")
		}
	}

	// Verify the aggregated signature with all of the public keys
	// In this scenario all of the key blobs need to be consolidated into a single key blob
	// The first key pair generated is used to perform the key blob consolidation (keyPairs[0])
	for i := 1; i < maxKeyPairs; i++ {
		keyPairs[0].PubKey.KeyBlobs[0] = append(keyPairs[0].PubKey.KeyBlobs[0], keyPairs[i].PubKey.KeyBlobs[0]...)
	}

	verifySingleRequest = &pb.VerifySingleRequest{
		PubKey: keyPairs[0].PubKey,
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_ECDSA_OTHER,
			Parameter: &pb.Mechanism_ECSGParameter{
				ECSGParameter: &pb.ECSGParm{
					Type: pb.ECSGParm_CkEcsgIbmBls,
				},
			},
		},
		Data:      msg,
		Signature: signSingleResponse.Signature,
	}

	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Println("Expected invalid signature error occurred")
		} else {
			panic("Invalid signature error was expected, but did not occur")
		}
	}

	// Output:
	// Generated BLS12-381 key pairs
	// Successfully created an aggregated signature from ten individual signatures
	// Successfully created an aggregated public key from ten individual public keys
	// Expected invalid signature error occurred
	// Expected invalid signature error occurred
}
