/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"testing"

	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/util"
)

// Test_rewrapKeyBlob re-encrypts generated key blobs with the new committed wrapping key that is contained within the HSM.
// Keys that have been re-encrypted can only be used (e.g., encrypt, decrypt) after the HSM has been finalized with the new
// committed wrapping key.
// See figure 8 on page 30 and page 41 of the "Enterprise PKCS#11 Library Structure" document for additional information.
// The instructions on how to obtain a copy of the "Enterprise PKCS#11 Library Structure" document is in the
// "EP11 Principles of Operation" section of the README.md file.
//
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

	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

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

	iv, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	// Encrypt data using the generated AES key blob. The encrypted data will be used later in the test.
	// The data will be decrypted by the re-wrapped AES key blob.
	// Obtain initialization vector for encrypt and decrypt operations

	plain := []byte("This text will be used to confirm a successful key blob re-encrypt operation")

	encryptRequest := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:   generateKeyResponse.Key,
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
		WrappedKey: generateKeyResponse.Key,
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

	// Output:
	// Generated original AES key that will be rewrapped
	// Encrypted message using the original wrapped AES key
	// Press Ctrl-c after the domain has been placed into the committed state in order to continue with the RewrapKeyBlob action
	// RewrapKeyBlob action has completed
	// Original wrapped AES key has been rewrapped with the new wrapping key
	// Press Ctrl-c after the card has been finalized in order to continue testing the new wrapped key
	// Encrypted message using the rewrapped AES key
	// Successfully decrypted new data with the rewrapped AES key
	// Successfully decrypted original data with the rewrapped AES key
}
