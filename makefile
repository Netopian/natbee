.PHONY: build
build: gennatbpf genfnatbpf
	go build -o ./bin/nb ./cmd/nb/main.go
	go build -o ./bin/nbd ./cmd/nbd/main.go

.PHONY: gennatbpf
gennatbpf:
	clang \
	-Wall \
	-I./ebpf/include \
	-O2 -emit-llvm -c ./ebpf/nb_nat.c -o -| llc -march=bpf -filetype=obj -o ./bin/nat_bpfel.o

.PHONY: genfnatbpf
genfnatbpf:
	clang \
	-Wall \
	-I./ebpf/include \
	-O2 -emit-llvm -c ./ebpf/nb_fnat.c -o -| llc -march=bpf -filetype=obj -o ./bin/fnat_bpfel.o