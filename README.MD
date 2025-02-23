# GO-PQC-BENCH

A repository to benchmark the performance of cryptography algorithm

## How to run

### running dsa version

```Bash
go test ./dsa -bench=BenchmarkGenKey1 -benchmem -benchtime=1s
```

### running kem version

```Bash
go test ./kem -bench=BenchmarkGenKey -benchmem -benchtime=1s
```

### using available script

You can use the bash script within each directory e.g. `./dsa/run-all.sh` or `./kem/run-all.sh` to easily run all benchmark function and directly producing all the result.
