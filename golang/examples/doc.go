/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

/*
	Package examples provide GREP11 function call examples.
	Regular function calls have four steps.
	The following is one example to generate a key:

	1 cryptoClient := pb.NewCryptoClient(conn)                   // create a crypto client
	2 Template := util.AttributeMap(ep11.EP11Attributes{...})    // create a template
	3 keyGenMsg, err := &pb.GenerateKeyRequest()                 // create RPC request parameters
	4 if err != nil {...}                                        // check for an error

*/
package examples
