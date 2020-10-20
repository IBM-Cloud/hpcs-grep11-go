# Overview

This repository contains software to be used to connect to the **IBM Cloud Hyper Protect Crypto Services**  offering. For more information regarding this service please review the [IBM Cloud Hyper Protect Services documentation](https://cloud.ibm.com/docs/services/hs-crypto?topic=hs-crypto-get-started). The package contained within this repository uses go modules, and therefore, this repository can be cloned into any local directory; there is no need to place it within your `GOPATH`.

# Contents

The contents of this repository are offered *as-is* and is subject to change at anytime.

For general information about "Enterprise PKCS #11 over gRPC" please see the official [documentation](https://cloud.ibm.com/docs/services/hs-crypto?topic=hs-crypto-enterprise_PKCS11_overview#grep11_intro)

# Code Examples

Included in this repository are working examples written in Go. The examples show how to use the **IBM Cloud Hyper Protect Services offering** to accomplish the following functions:

* Key generation
* Encrypt and decrypt
* Sign and verify
* Wrap and unwrap keys
* Derive keys
* Build message digest
* Retrieve mechanism information
  
## Example setup and execution

1. [Install Golang](https://golang.org/doc/install).

2. Clone this repository into a local directory of your choice. Go modules are used for this
   repository, so there is no need to place the cloned repository in your `GOPATH`.

3. Update the following information in the [examples/server_test.go](examples/server_test.go#L30) file.  

	*NOTE: This information can obtained by logging in to your IBM Cloud account and viewing your Hyper Protect Crypto Serverices instance and IAM information. See the [GREP11 API documentation](https://cloud.ibm.com/docs/services/hs-crypto?topic=hs-crypto-grep11-api-ref) for more information about GREP11*.

	```Golang
	// The following IBM Cloud HPCS service items need to be changed prior to running the sample program
	const address = "<grep11_server_address>:<port>"

	var callOpts = []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
		grpc.WithPerRPCCredentials(&util.IAMPerRPCCredentials{
			APIKey:   "<ibm_cloud_apikey>",
			Endpoint: "<https://<iam_ibm_cloud_endpoint>",
			Instance: "<hpcs_instance_id>",
		}),
	}
	```
		
4. Change your working directory (cd) to `<path>/hpcs-grep11-go/examples`

5. Execute the examples by issuing the command: `go test -v`

6. The sample program produces output similar to the following:

    ```=== RUN   Test_rewrapKeyBlob
    server_test.go:1144: 
         
        Skipping the rewrapKeyBlob test. To enable, comment out the t.Skipf and message lines within the Test_rewrapKeyBlob test
        
        NOTE: This test contains two pauses that require the user to type CTRL-c after ensuring
              that the stated pre-requisite activity has been completed.  There needs to be 
              coordination with your HPCS cloud service contact in order to place your HSM
              into the required states.
         
    --- SKIP: Test_rewrapKeyBlob (0.00s)
    === RUN   Example_bip32_Base
    --- PASS: Example_bip32_Base (1.46s)
    === RUN   Example_bip32_KeyDerivation
    --- PASS: Example_bip32_KeyDerivation (0.15s)
    === RUN   Example_bip32_Cross_SignVerify
    --- PASS: Example_bip32_Cross_SignVerify (0.53s)
    === RUN   Example_getMechanismInfo
    --- PASS: Example_getMechanismInfo (0.08s)
    === RUN   Example_generateGenericKey
    --- PASS: Example_generateGenericKey (0.07s)
    === RUN   Example_encryptAndDecryptUsingAES
    --- PASS: Example_encryptAndDecryptUsingAES (0.21s)
    === RUN   Example_digest
    --- PASS: Example_digest (0.15s)
    === RUN   Example_signAndVerifyUsingRSAKeyPair
    --- PASS: Example_signAndVerifyUsingRSAKeyPair (0.18s)
    === RUN   Example_signAndVerifyUsingDSAKeyPair
    --- PASS: Example_signAndVerifyUsingDSAKeyPair (1.08s)
    === RUN   Example_deriveKeyUsingDHKeyPair
    --- PASS: Example_deriveKeyUsingDHKeyPair (1.97s)
    === RUN   Example_signAndVerifyUsingECDSAKeyPair
    --- PASS: Example_signAndVerifyUsingECDSAKeyPair (0.13s)
    === RUN   Example_signAndVerifyToTestErrorHandling
    --- PASS: Example_signAndVerifyToTestErrorHandling (0.13s)
    === RUN   Example_wrapAndUnwrapKey
    --- PASS: Example_wrapAndUnwrapKey (0.17s)
    === RUN   Example_deriveKey
    --- PASS: Example_deriveKey (0.18s)
    === RUN   Example_slip10DeriveKey
    --- PASS: Example_slip10DeriveKey (1.64s)
    === RUN   Example_slip10_invalid_signAndVerify
    --- PASS: Example_slip10_invalid_signAndVerify (0.48s)
    === RUN   Example_slip10_cross_signAndVerify
    --- PASS: Example_slip10_cross_signAndVerify (0.43s)
    === RUN   Example_tls
    --- PASS: Example_tls (0.11s)
    PASS
    ok      github.com/IBM-Cloud/hpcs-grep11-go/examples    12.633s
    ```

**NOTE:** By default the rewrapKeyBlob test is skipped.  This test acts as sample code that can be used to reencrypt your existing keys with a new HSM wrapping key.  See figure 8 on page 27 and page 37 in https://www.ibm.com/downloads/cas/WXRDPRAN for additional information on how existing keys can be reencrypted.  This operation requires coordination between the end-user and the **IBM Cloud Hyper Protect Crypto Services** instance's administrator(s).

## General Function Call Workflow

GREP11 can perform encrypt, decrypt, digest, sign and verify operations. For each operation, there are a series of sub-operations or functions.  

For example, the *Encrypt* operation consists of *EncryptInit()*, *Encrypt()*, *EncryptUpdate()*, *EncryptFinal()* and *EncryptSingle()* sub-operations.

#### GREP11 sub-operations for Encrypt:

- *Encrypt***Init()** is used to initialize an operation

- *Encrypt()* is used to encrypt data without the need to perform *EncryptUpdate()* or *EncryptFinal()* sub-operations. *EncryptInit()* must be run prior to the *Encrypt()* call

- *Encrypt***Update()** is used to perform update operations as part of a multi-part operation

- *Encrypt***Final()** is used to perform final operations as part of a multi-part operation

- *Encrypt***Single()** is an IBM EP11 extension to the standard PKCS#11 specification and used to perform a single call without the need to use the **Init**, **Update**, and **Final** sub-operations

The following diagram shows the three calling sequence flows that can be used for *Encrypt*, *Decrypt*, *Digest*, *Sign* and *Verify* operations:

![function work flow](func_workflow.svg)