#!/bin/bash
curl -v \
	-X POST \
	-H "Content-Type: application/json" \
	--data @test/request.json \
	"https://maajepio.eus.attest.azure.net/attest/SevSnpVm?api-version=2022-08-01"
