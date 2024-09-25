/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"fmt"
	"reflect"

	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/util"
)

// Example_reencryptSingle demonstrates a function that is unique to EP11 and is not part of the
// PKCS #11 specification.  Data that has been encrypted with Key "A" can be sent to the remote HSM
// along with Key "A" and Key "B".  The remote HSM decrypts the data using Key "A" and then encrypts
// the data using Key "B".  The encrypted data that is returned from the remote HSM is now encrypted
// by Key "B"
// Flow: connect, generate Key "A", generate Key "B", encrypt sample data using Key "A",
// reencrypt data with Key "B", decrypt reencrypted data using Key "B"
func Example_reencryptSingle() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	keyLen := 256 // 256-bit AES key

	// Setup the AES key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN: keyLen / 8,
		ep11.CKA_ENCRYPT:   true,
		ep11.CKA_DECRYPT:   true,
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	// Generate Key "A"
	generateKeyResponseA, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated AES Key 'A'")

	// Generate Key "B"
	generateKeyResponseB, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated AES Key 'B'")

	// Obtain initialization vector for encrypt and decrypt operations
	ivA, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}
	fmt.Println("Generated IV for Key 'A'")

	plain := []byte("Hello, this is a very long and creative message")

	encryptSingleRequest := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(ivA)},
		Key:   generateKeyResponseA.Key, // Using Key "A" to encrypt the data
		Plain: plain,
	}

	// Encrypt the sample data using Key "A"
	encryptSingleResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("EncryptSingle error: %s", err))
	}

	fmt.Println("Encrypted data using Key 'A'")

	// Obtain initialization vector for encrypt and decrypt operations
	ivB, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}
	fmt.Println("Generated IV for Key 'B'")

	reencryptSingleRequest := &pb.ReencryptSingleRequest{
		DecMech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(ivA)},
		EncMech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(ivB)},
		DecKey:   generateKeyResponseA.Key,       // Decrypt using Key "A"
		EncKey:   generateKeyResponseB.Key,       // Reencrpt using Key "B"
		Ciphered: encryptSingleResponse.Ciphered, // Data that was encrypted using Key "A"
	}

	// Reencrypt the data using Key "B"
	reencryptSingleResponse, err := cryptoClient.ReencryptSingle(context.Background(), reencryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("ReencryptSingle error: %s", err))
	}

	fmt.Println("Successfully reencrypted the data using Key 'B'")

	// Confirm that the data decrypted using Key "B" matches the original sample data
	decryptSingleRequest := &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(ivB)},
		Key:      generateKeyResponseB.Key,
		Ciphered: reencryptSingleResponse.Reciphered,
	}

	// Decrypt the data using Key "B"
	decryptSingleResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("DecryptSingle error: %s", err))
	}

	plaintext := decryptSingleResponse.Plain

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing original plain text to decrypted data"))
	}

	fmt.Printf("Successfully decrypted data using Key 'B'\n%s\n", plaintext)

	// Output:
	// Generated AES Key 'A'
	// Generated AES Key 'B'
	// Generated IV for Key 'A'
	// Encrypted data using Key 'A'
	// Generated IV for Key 'B'
	// Successfully reencrypted the data using Key 'B'
	// Successfully decrypted data using Key 'B'
	// Hello, this is a very long and creative message
}
