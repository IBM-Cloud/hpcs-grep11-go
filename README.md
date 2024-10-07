# Overview

This repository contains software used to connect and interact with the **IBM Cloud Hyper Protect Crypto Services**  offering. For more information regarding this service please review the [IBM Cloud Hyper Protect Services documentation](https://cloud.ibm.com/docs/services/hs-crypto?topic=hs-crypto-get-started). The contents of this repository use go modules, and therefore, this repository can be cloned into any local directory; there is no need to place it in your `GOPATH`.

# Contents

The contents of this repository are offered *as-is* and are subject to change at anytime.

For general information about "Enterprise PKCS #11 over gRPC" (GREP11), please see the official [documentation](https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-introduce-cloud-hsm#access-cloud-hsm-pkcs11)

To view the documentation of the hpcs-grep11 Go module contained in this repository, type the command `godoc` (requires the installation of Go) from the cloned repository's main directory
and open a browser to [http://localhost:6060/pkg/github.com/IBM-Cloud/hpcs-grep11-go/](http://localhost:6060/pkg/github.com/IBM-Cloud/hpcs-grep11-go/).  See step 1 in the [section below](#example-setup-and-execution) for instructions on how to install Go.

# Code Examples

Included in this repository are working examples written in Go. The examples demonstrate how to use the **IBM Cloud Hyper Protect Services offering** to accomplish the following operations:

* Key generation
* Encrypt and decrypt
* Sign and verify
* Wrap and unwrap keys
* Derive keys
* Build message digest
* Retrieve mechanism information
* Generate random data

In addition there are examples that demonstrate the use of **BIP32**, **SLIP10**, **BLS12-381**, **Kyber**,
**Dilithium**, **Schnorr**, and **Edwards Curve**. 

**NOTE: Depending on what type of IBM Crypto Expresss card is being used for your HPCS instance,
the example code may skip tests.  This is documented in the example code.**
  
## Example setup and execution

1. [Install Go](https://golang.org/doc/install).

2. Clone this repository into a local directory of your choice. Go modules are used for this
   repository, so there is no need to place the cloned repository in your `GOPATH`.

3. Prior to running the sample code, there are two environment variables that must be set to ensure that the connection is authorized:

    - **GREP11_ADDRESS** - The full Enterprise PKCS #11 endpoint URL. This can be obtained by navigating
    to your HPCS instance's main page via the IBM Cloud UI, expanding the *Enterprise PKCS #11 endpoint URL*
    section and copying either the *Public* or *Private* URL.  If the URL does not contain a port then append `:443`
    to the Enterprise PKCS #11 endpoint URL.  Example: `7fc144ef-ed7c-4be1-9a35-748b40477dcd.ep11.hs-crypto.appdomain.cloud:443`

    NOTE: The use of either the public or private endpoint is dependent on what network is being used to access the remote server

    - **GREP11_APIKEY** - An IAM API key associated with the HPCS instance being accessed.

    Optionally, The values of the two environment variables listed above can be hardcoded in the `main.go` file. Replace the
    values of the `ClientConfig.Address` and `ClientConfig.APIKey` variable fields with the values related to your HPCS instance.
		

4. From the `<path>/hpcs-grep11-go/examples` directory, execute the examples by issuing the command: `go test -v`.

5. The sample program produces output similar to the following:

    ```
    .
    .
    .
    === RUN   Example_signVerify_ECDSA_ESP
    --- PASS: Example_signVerify_ECDSA_ESP (0.09s)
    === RUN   Example_signVerify_ECDSA_PSP
    --- PASS: Example_signVerify_ECDSA_PSP (0.09s)
    === RUN   Example_signVerify_ECDSA_PMP
    --- PASS: Example_signVerify_ECDSA_PMP (0.02s)
    === RUN   Example_signVerify_TestErrorHandling
    --- PASS: Example_signVerify_TestErrorHandling (0.02s)
    === RUN   Example_slip10DeriveKey
    --- PASS: Example_slip10DeriveKey (0.99s)
    === RUN   Example_slip10CrossSignAndVerify
    --- PASS: Example_slip10CrossSignAndVerify (0.20s)
    === RUN   Example_tls
    --- PASS: Example_tls (0.02s)
    === RUN   Example_wrapUnwrap_AESKey_WithRSA
    --- PASS: Example_wrapUnwrap_AESKey_WithRSA (0.09s)
    === RUN   Example_wrapUnwrap_AttributeBoundKey
    --- PASS: Example_wrapUnwrap_AttributeBoundKey (0.07s)
    === RUN   Example_importExport_AESKey
    --- PASS: Example_importExport_AESKey (0.00s)
    === RUN   Example_export_RSAPrivKey
    --- PASS: Example_export_RSAPrivKey (0.18s)
    === RUN   Example_export_ECPrivKey
    --- PASS: Example_export_ECPrivKey (0.02s)
    === RUN   Example_import_RSA_Keypair
    --- PASS: Example_import_RSA_Keypair (2.63s)
    === RUN   Example_import_EC_Keypair
    --- PASS: Example_import_EC_Keypair (0.01s)
    PASS
    ok  	github.com/IBM-Cloud/hpcs-grep11-go/v2/examples	22.285s
    ```

**NOTE:** By default the rewrapKeyBlob test is skipped. This test acts as sample code that can be used to reencrypt your existing keys with a new HSM wrapping key. See figure 8 on page 27 and page 37 in the "EP11 Principles of Operation" document for additional information on how existing keys can be reencrypted. Instructions on how to obtain a copy of the "EP11 Principles of Operation" document are listed in the [section below](#ep11-principles-of-operation). In order to run this test, there must be coordination between the end-user and the **IBM Cloud Hyper Protect Crypto Services** instance's administrator(s).

## General Function Call Workflow

GREP11 can perform encrypt, decrypt, digest, sign and verify operations. For each operation, there are a series of sub-operations or functions.  

For example, the *Encrypt* operation consists of *EncryptInit()*, *Encrypt()*, *EncryptUpdate()*, *EncryptFinal()* and *EncryptSingle()* sub-operations.

#### GREP11 sub-operations for Encrypt:

- *Encrypt***Init()** is used to initialize an operation and must be run prior to *Encrypt()*, *EncryptUpdate()*, or *EncryptFinal()* calls

- *Encrypt()* is used to encrypt data without the need to perform *EncryptUpdate()* or *EncryptFinal()* sub-operations.

- *Encrypt***Update()** is used to perform update operations as part of a multi-part operation

- *Encrypt***Final()** is used to perform final operations as part of a multi-part operation

- *Encrypt***Single()** is an IBM EP11 extension to the standard PKCS #11 specification and used to perform a single call without the need to use the **Init**, **Update**, and **Final** sub-operations

The following diagram shows the three calling sequence flows that can be used for *Encrypt*, *Decrypt*, *Digest*, *Sign* and *Verify* operations:

![function work flow](func_workflow.svg)

## EP11 Principles of Operation

For those that would like to have a low-level understanding of EP11, the EP11 Principles of Operation are provided
in the "Enterprise PKCS#11 (EP11) Library structure" pdf document.

The following steps outline how to obtain a copy of this document:
1. Go to https://www.ibm.com/resources/mrs/assets?source=ibm-zesp&lang=en_US. Use your IBMid and password to login.
2. Click the "I agree" checkbox and then click "I Confirm".
3. Click the "Download" link to the right of "IBM Z EP11 Support Program files".
4. Select the directory where you would like the zip file to be downloaded and save.
5. Unzip the support program zip file.
6. "cd" to the the unzipped directory.
7. Open the "ep11-structure.pdf" document to view the EP11 Principles of Operation

There is a supplemental document called "ep11-wire.txt" that contains additional information on EP11.