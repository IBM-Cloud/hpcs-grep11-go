/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"crypto/rand"
	"encoding/asn1"
	"fmt"

	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/util"
	go_schnorr "github.com/Zilliqa/gozilliqa-sdk/v3/schnorr"
	"github.com/btcsuite/btcd/btcec/v2"
)

// This file contains examples of sign and verify operations using the Schnorr algorithm and EC keys.
// One cipher flow is demonstrated for Schnorr sign/verify tests: EP11 single-part (ESP)
//
// The test name has a suffix of ESP that denotes the cipher flow used in the test.
// Refer to the ciper flow diagram in README.md.
//
// For Schnorr signatures, the data to be signed, the key blob used to sign, and the
// mechanism parameter must all fit within 12 KB for CEX7 cards and 24KB for CEX8 cards.
// If the size of the above items exceeds the max buffer size then
// a CKR_MECHANISM_INVALID error occurs.
// In addition, only 256-bit EC curves can be used for Schnorr sign and verify operations.

// Example_signVerify_Schnorr_ECDSA_S256_ESP generates an EC key pair (256-bit EC curve)
// and performs sign and verify operations on data using the Schnorr algorithm.
//
// The Schnorr signature algorithm demonstrated in this example:
// ECSG_IBM_ECSDSA_S256:
// - BSI TR03111 ECSDSA
// - No prehashing; SHA-256 only
//
// Flow: connect, generate EC key pair, sign EP11 single-part data, verify EP11 single-part
// data using remote HSM
//
// See "Cipher Flow 1" of the flow diagram in README.md
func Example_signVerify_Schnorr_ECDSA_S256_ESP() {
	var messageLength int = (6 * 1024)

	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	ecParameters, err := asn1.Marshal(util.OIDNamedCurveSecp256k1)
	if err != nil {
		panic(fmt.Errorf("Marshal error: %s", err))
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

	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %+v %s", generateECKeypairRequest, err))
	}

	fmt.Println("Generated EC key pair")

	signData := make([]byte, messageLength)
	rand.Read(signData)

	signSingleRequest := &pb.SignSingleRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_ECDSA_OTHER,
			Parameter: &pb.Mechanism_ECSGParameter{
				ECSGParameter: &pb.ECSGParm{
					Type: pb.ECSGParm_CkEcsgIbmEcsdsaS256,
				},
			},
		},
		PrivKey: generateKeyPairResponse.PrivKey,
		Data:    signData,
	}

	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	fmt.Println("Message was successfully signed")

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_ECDSA_OTHER,
			Parameter: &pb.Mechanism_ECSGParameter{
				ECSGParameter: &pb.ECSGParm{
					Type: pb.ECSGParm_CkEcsgIbmEcsdsaS256,
				},
			},
		},
		PubKey:    generateKeyPairResponse.PubKey,
		Data:      signData,
		Signature: signSingleResponse.Signature,
	}

	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("VerifySingle error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Signature was successfully verified using HPCS remote HSM")

	// Output:
	// Generated EC key pair
	// Message was successfully signed
	// Signature was successfully verified using HPCS remote HSM
}

// Example_signVerify_Schnorr_ECDSA_COMPR_MULTI_ESP generates an EC key pair (256-bit EC curve)
// and performs sign and verify operations on data using the Schnorr algorithm.
//
// ECSG_IBM_ECSDSA_COMPR_MULTI:
// - BSI TR03111 ECSDSA (2012)
// - Internally using compressed key format includes signing party’s public key
// - No prehashing; SHA-256 only
//
// Flow: connect, generate EC key pair, sign EP11 single-part data, verify EP11 single-part
// data using remote HSM, software verify data using Zilla library
//
// See "Cipher Flow 1" of the flow diagram in README.md
func Example_signVerify_Schnorr_ECDSA_COMPR_MULTI_ESP() {
	var messageLength int = (6 * 1024)

	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	ecParameters, err := asn1.Marshal(util.OIDNamedCurveSecp256k1)
	if err != nil {
		panic(fmt.Errorf("Marshal error: %s", err))
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

	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %+v %s", generateECKeypairRequest, err))
	}

	fmt.Println("Generated EC key pair")

	signData := make([]byte, messageLength)
	rand.Read(signData)

	signSingleRequest := &pb.SignSingleRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_ECDSA_OTHER,
			Parameter: &pb.Mechanism_ECSGParameter{
				ECSGParameter: &pb.ECSGParm{
					Type: pb.ECSGParm_CkEcsgIbmEcsdsaComprMulti,
				},
			},
		},
		PrivKey: generateKeyPairResponse.PrivKey,
		Data:    signData,
	}

	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	fmt.Println("Message was successfully signed")

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_ECDSA_OTHER,
			Parameter: &pb.Mechanism_ECSGParameter{
				ECSGParameter: &pb.ECSGParm{
					Type: pb.ECSGParm_CkEcsgIbmEcsdsaComprMulti,
				},
			},
		},
		PubKey:    generateKeyPairResponse.PubKey,
		Data:      signData,
		Signature: signSingleResponse.Signature,
	}

	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("VerifySingle error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Signature was successfully verified using HPCS remote HSM")

	if verifyZilliqa(generateKeyPairResponse.PubKey.KeyBlobs[0], signData, signSingleResponse.Signature) != true {
		panic(fmt.Errorf("Signature verification error using software library"))
	}

	fmt.Println("Signature was successfully verified using software library")

	// Output:
	// Generated EC key pair
	// Message was successfully signed
	// Signature was successfully verified using HPCS remote HSM
	// Verified with Zilliqa SDK
	// Signature was successfully verified using software library
}

func verifyZilliqa(spki []byte, signData []byte, sign []byte) bool {

	publicKey, err := util.GetECPointFromSPKI(spki)
	if err != nil {
		panic(fmt.Errorf("Failed getting public key: [%s]", err))
	}
	pubkey, err := btcec.ParsePubKey(publicKey)
	if err != nil {
		panic(fmt.Errorf("Failed parsing public key [%s]", err))
	}

	compressedPubKey := pubkey.SerializeCompressed()
	length := len(sign)
	r := sign[:length/2]
	s := sign[length/2:]

	// Verify signature using Zilliqa go sdk at https://github.com/Zilliqa/gozilliqa-sdk
	if go_schnorr.Verify(compressedPubKey, signData, r, s) {
		fmt.Println("Verified with Zilliqa SDK")
		return true
	}

	fmt.Println("Failed verifying signature with Zilliqa SDK")

	return false
}
