module github.com/sbezverk/nftableslib

go 1.12

require (
	github.com/google/gopacket v1.1.17
	github.com/google/nftables v0.0.0-20191019065353-35de0a609f16
	github.com/google/uuid v1.1.1
	github.com/sbezverk/nftableslib/e2e/setenv v0.0.0-20191010164456-029e0d78cdb1
	github.com/vishvananda/netlink v1.0.0
	github.com/vishvananda/netns v0.0.0-20190625233234-7109fa855b0f
	golang.org/x/net v0.0.0-20191028085509-fe3aa8a45271
	golang.org/x/sys v0.0.0-20191029155521-f43be2a4598c
)

replace github.com/google/nftables => ../nftables
