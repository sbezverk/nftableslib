module github.com/sbezverk/nftableslib/e2e

go 1.13

require (
	github.com/sbezverk/nftableslib/e2e/setenv v0.0.0
	github.com/vishvananda/netns v0.0.0-20190625233234-7109fa855b0f
)

replace github.com/sbezverk/nftableslib/e2e/setenv => ./setenv
