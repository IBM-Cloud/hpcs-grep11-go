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

// This file contains examples of sign and verify operations using Dilithium keys.
// Two cipher flows are demonstrated for Dilithium keys: EP11 single-part (ESP) and PKCS#11 single-part (PSP)
// NOTE: PKCS#11 multi-part is not supported for Dilithium keys
//
// Each test name has a suffix of ESP or PSP denoting the cipher flow used in the test.
// Refer to the ciper flow diagram in README.md.

// NOTE: Using the Dilithium mechanism is hardware and firmware dependent.  The test requires
// the use of the CKM_IBM_DILITHIUM mechanism.  If the mechanism is not supported for the
// hardware being used by the server, the test will be skipped.
//
// Generating Dilithium key pairs and sign and verify operation using Dilithium keys
// require the use of the CKM_IBM_DILITHIUM mechanism.
//
// IBM Crypto Express Card support for Dilithium
// CEX6: No support
// CEX7: Only supports the OIDDilithiumHigh (1.3.6.1.4.1.2.267.1.6.5) round 2 strength
// CEX8:
// OIDDilithiumHigh    (1.3.6.1.4.1.2.267.1.6.5) round 2 strength
// OIDDilithium87      (1.3.6.1.4.1.2.267.1.8.7) round 2 strength
// OIDDilithiumR3Weak  (1.3.6.1.4.1.2.267.7.4.4) round 3 strength
// OIDDilithiumR3Rec   (1.3.6.1.4.1.2.267.7.6.5) round 3 strength
// OIDDilithiumR3VHigh (1.3.6.1.4.1.2.267.7.8.7) round 3 strength

// Test_signVerify_DilithiumKey_ESP generates a Dilithium key pair
// then uses the key pair to sign and verify a sample message
// Flow: connect, generate Dilithium key pair, sign EP11 single-part data, verify EP11 single-part data
// See "Cipher Flow 1" of the flow diagram in README.md
func Test_signVerify_Dilithium_ESP(t *testing.T) {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	type dilithiumStrengths struct {
		Name string
		OID  asn1.ObjectIdentifier
	}

	// Dilithium strengths to test
	strengths := []dilithiumStrengths{
		{"OIDDilithiumHigh", util.OIDDilithiumHigh},
		{"OIDDilithium87", util.OIDDilithium87},
		{"OIDDilithiumR3Weak", util.OIDDilithiumR3Weak},
		{"OIDDilithiumR3Rec", util.OIDDilithiumR3Rec},
		{"OIDDilithiumR3VHigh", util.OIDDilithiumR3VHigh},
	}

	// Check to see if the CKM_IBM_DILITHIUM mechanism is supported on the remote HSM
	if !util.MechanismExists(cryptoClient, ep11.CKM_IBM_DILITHIUM) {
		t.Skip("Dilithium mechanism is not supported on the remote HSM")
	}

	for _, strength := range strengths {
		// Strengths OIDDilithium87, OIDDilithiumR3Weak, OIDDilithiumR3Rec, and OIDDilithiumR3VHigh
		// are only supported on IBM Crypto Express CEX8 cards, so check that support is available
		if strength.Name != "OIDDilithiumHigh" &&
			!util.MechanismExists(cryptoClient, ep11.CKM_IBM_KYBER) { // The CKM_IBM_KYBER mechanism only exists on CEX8 cards
			fmt.Printf("Strength %s is not supported on the remote HSM\n", strength.Name)
			continue
		}

		// Setup PQC parameter and key templates
		dilithiumStrengthParam, err := asn1.Marshal(strength.OID)
		if err != nil {
			panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
		}

		publicKeyTemplate := ep11.EP11Attributes{
			ep11.CKA_IBM_PQC_PARAMS: dilithiumStrengthParam,
			ep11.CKA_VERIFY:         true, // allow public key to verify signatures
		}

		privateKeyTemplate := ep11.EP11Attributes{
			ep11.CKA_SIGN:      true, // allow private key to perform sign operations
			ep11.CKA_PRIVATE:   true,
			ep11.CKA_SENSITIVE: true,
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

		fmt.Printf("Generated Dilithium key pair using strength %s\n", strength.Name)

		signData := []byte("This data needs to be signed")

		signSingleRequest := &pb.SignSingleRequest{
			Mech:    &pb.Mechanism{Mechanism: ep11.CKM_IBM_DILITHIUM},
			PrivKey: generateDilKeyPairResponse.PrivKey,
			Data:    signData,
		}

		// Sign the data
		signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
		if err != nil {
			panic(fmt.Errorf("SignSingle error: %s", err))
		}

		fmt.Printf("Data signed using strength %s\n", strength.Name)

		verifySingleRequest := &pb.VerifySingleRequest{
			Mech:      &pb.Mechanism{Mechanism: ep11.CKM_IBM_DILITHIUM},
			PubKey:    generateDilKeyPairResponse.PubKey,
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

		fmt.Printf("Data verified using strength %s\n", strength.Name)
	}

	// Output:
	// Generated Dilithium key pair using strength ...
	// Data signed using strength ...
	// Data verified using strength ...
}

// Test_signVerify_DilithiumKey_PSP generates a Dilithium key pair
// then uses the key pair to sign and verify a sample message
// Flow: connect, generate Dilithium key pair, sign PKCS #11 single-part data, verify PKCS #11 single-part data
// See "Cipher Flow 2" of the flow diagram in README.md
func Test_signVerify_Dilithium_PSP(t *testing.T) {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	type dilithiumStrengths struct {
		Name string
		OID  asn1.ObjectIdentifier
	}

	// Dilithium strengths to test
	strengths := []dilithiumStrengths{
		{"OIDDilithiumHigh", util.OIDDilithiumHigh},
		{"OIDDilithium87", util.OIDDilithium87},
		{"OIDDilithiumR3Weak", util.OIDDilithiumR3Weak},
		{"OIDDilithiumR3Rec", util.OIDDilithiumR3Rec},
		{"OIDDilithiumR3VHigh", util.OIDDilithiumR3VHigh},
	}

	// Check to see if the CKM_IBM_DILITHIUM mechanism is supported on the remote HSM
	if !util.MechanismExists(cryptoClient, ep11.CKM_IBM_DILITHIUM) {
		t.Skip("Dilithium mechanism is not supported on the remote HSM")
	}

	for _, strength := range strengths {
		// Strengths OIDDilithium87, OIDDilithiumR3Weak, OIDDilithiumR3Rec, and OIDDilithiumR3VHigh
		// are only supported on IBM Crypto Express CEX8 cards, so check that support is available
		if strength.Name != "OIDDilithiumHigh" &&
			!util.MechanismExists(cryptoClient, ep11.CKM_IBM_KYBER) { // The CKM_IBM_KYBER mechanism only exists on CEX8 cards
			fmt.Printf("Strength %s is not supported on the remote HSM\n", strength.Name)
			continue
		}

		// Setup PQC parameter and key templates
		dilithiumStrengthParam, err := asn1.Marshal(strength.OID)
		if err != nil {
			panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
		}

		publicKeyTemplate := ep11.EP11Attributes{
			ep11.CKA_IBM_PQC_PARAMS: dilithiumStrengthParam,
			ep11.CKA_VERIFY:         true, // allow public key to verify signatures
		}

		privateKeyTemplate := ep11.EP11Attributes{
			ep11.CKA_SIGN:      true, // allow private key to perform sign operations
			ep11.CKA_PRIVATE:   true,
			ep11.CKA_SENSITIVE: true,
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

		fmt.Printf("Generated Dilithium key pair using strength %s\n", strength.Name)

		signInitRequest := &pb.SignInitRequest{
			Mech:    &pb.Mechanism{Mechanism: ep11.CKM_IBM_DILITHIUM},
			PrivKey: generateDilKeyPairResponse.PrivKey,
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

		fmt.Printf("Data signed using strength %s\n", strength.Name)

		verifyInitRequest := &pb.VerifyInitRequest{
			Mech:   &pb.Mechanism{Mechanism: ep11.CKM_IBM_DILITHIUM},
			PubKey: generateDilKeyPairResponse.PubKey,
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

		fmt.Printf("Data verified using strength %s\n", strength.Name)
	}

	// Output:
	// Generated Dilithium key pair using strength ...
	// Data signed using strength ...
	// Data verified using strength ...
}
