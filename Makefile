CCOMPILER = clang
GOCOMPILER = go
CGO_ENV = CGO_ENABLED=0
STRIP = llvm-strip

.PHONY: all
.DEFAULT_GOAL := build_prog

build_ebpf: bpf/bpf.c
	$(CCOMPILER) -O2 -target bpf -c $^ -o pkg/bpf.o
	$(STRIP) -g pkg/bpf.o

build_prog: build_ebpf
	CGO_ENABLED=0 go build -o ctnctl ./

lint:
	golangci-lint run

clean:
	$(RM) pkg/bpf.o ctnctl
