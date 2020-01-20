module github.com/sbezverk/nftableslib

go 1.12

require (
	github.com/google/gopacket v1.1.17
	github.com/google/nftables v0.0.0-20200114154937-bf895afbc6b3
	github.com/google/uuid v1.1.1
	github.com/mdlayher/netlink v1.0.0 // indirect
	github.com/sbezverk/nftableslib/e2e/setenv v0.0.0-20191010164456-029e0d78cdb1 // indirect
	github.com/vishvananda/netlink v1.0.0
	github.com/vishvananda/netns v0.0.0-20190625233234-7109fa855b0f
	golang.org/x/net v0.0.0-20191209160850-c0dbc17a3553
	golang.org/x/sys v0.0.0-20191220220014-0732a990476f
)

replace github.com/google/nftables => ../nftables
