# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

build-protos:
	@echo "=== Building the proto bindings ==="
	protoc  protos/*.proto \
	        -Iprotos \
	        -Ivendor/github.com/gogo/protobuf/gogoproto \
	  --gogofast_out=plugins=grpc,\
Mgoogle/protobuf/descriptor.proto=github.com/gogo/protobuf/protoc-gen-gogo/descriptor:./golang/grpc
	gofmt -w -s golang/ep11