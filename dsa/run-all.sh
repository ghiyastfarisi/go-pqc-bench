#!/bin/bash

go test . -bench=BenchmarkGenKey1 -benchmem -benchtime=1s
go test . -bench=BenchmarkGenKey2 -benchmem -benchtime=1s
go test . -bench=BenchmarkGenKey3 -benchmem -benchtime=1s
go test . -bench=BenchmarkSign1 -benchmem -benchtime=1s
go test . -bench=BenchmarkSign2 -benchmem -benchtime=1s
go test . -bench=BenchmarkSign3 -benchmem -benchtime=1s
go test . -bench=BenchmarkVerify1 -benchmem -benchtime=1s
go test . -bench=BenchmarkVerify2 -benchmem -benchtime=1s
go test . -bench=BenchmarkVerify3 -benchmem -benchtime=1s