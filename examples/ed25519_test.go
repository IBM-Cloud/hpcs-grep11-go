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

// This file contains examples of sign and verify operations using EC Edwards Curve keys.
// EC Edwards Curve sign and verify operations require the use of the CKM_IBM_ED25519_SHA512 mechanism.
// Two cipher flows are demonstrated for EC EdwardsCurve keys:
// EP11 single-part (ESP) and PKCS#11 single-part (PSP)
// NOTE: PKCS#11 multi-part is not supported for EC Edwards Curve keys
//
// Each test name has a suffix of ESP or PSP denoting the cipher flow used in the test.
// Refer to the ciper flow diagram in README.md.

// Example_signVerify_EC_EdwardsCurve_ESP generates an EC key pair using
// the Edwards curve and uses the key pair to sign and verify data
// Flow: connect, generate EC key pair, sign EP11 single-part data, verify EP11 single-part data
// See "Cipher Flow 1" of the flow diagram in README.md
func Example_signVerify_EC_EdwardsCurve_ESP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	ecParameters, err := asn1.Marshal(util.OIDNamedCurveED25519)
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

	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated EC key pair using Edwards curve")

	signData := []byte("This data needs to be signed")

	signSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_IBM_ED25519_SHA512},
		PrivKey: generateKeyPairResponse.PrivKey,
		Data:    signData,
	}

	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	fmt.Println("Data signed")

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_IBM_ED25519_SHA512},
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
	// Generated EC key pair using Edwards curve
	// Data signed
	// Data verified
}

// Example_signVerify_EC_EdwardsCurve_PSP generates an EC key pair
// using the Edwards curve and uses the key pair to sign and verify data
// Flow: connect, generate EC key pair, sign PKCS #11 single-part data, verify PKCS #11 single-part data
// See "Cipher Flow 2" of the flow diagram in README.md
func Example_signVerify_EC_EdwardsCurve_PSP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	ecParameters, err := asn1.Marshal(util.OIDNamedCurveED25519)
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

	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated EC key pair using Edwards curve")

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_IBM_ED25519_SHA512},
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
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_IBM_ED25519_SHA512},
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
	// Generated EC key pair using Edwards curve
	// Data signed
	// Data verified
}
