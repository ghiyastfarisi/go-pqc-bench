#!/bin/bash

go test . -bench=BenchmarkGenKey -benchmem -benchtime=1s
go test . -bench=BenchmarkEncap -benchmem -benchtime=1s
go test . -bench=BenchmarkDecap -benchmem -benchtime=1s