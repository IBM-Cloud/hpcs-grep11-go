# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

build-protos:
	@echo "=== Building the proto bindings ==="
	rm -rf vendor
	go mod vendor
	protoc  protos/*.proto \
	        -Iprotos \
	        -Ivendor/github.com/gogo/protobuf/gogoproto \
	        --gogofast_out=plugins=grpc,Mgoogle/protobuf/descriptor.proto=github.com/gogo/protobuf/protoc-gen-gogo/descriptor:./grpc
	gofmt -w -s ep11
	rm -rf vendor