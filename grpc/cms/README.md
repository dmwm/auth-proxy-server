This area contains vry basic gRPC service data. Please refer to
`service.proto` for details. To generate go code out of proto file
please use the following command:
```
protoc -I=$PWD --go_out=plugins=grpc:$PWD $PWD/service.proto
```
