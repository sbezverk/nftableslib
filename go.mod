module github.com/sbezverk/nftableslib

go 1.12

require (
	github.com/google/nftables v0.0.0-20190720163532-c123f7dc7d72
	github.com/jsimonetti/rtnetlink v0.0.0-20190606172950-9527aa82566a // indirect
	github.com/mdlayher/netlink v0.0.0-20190617153422-f82a9b10b2bc // indirect
	github.com/vishvananda/netns v0.0.0-20190625233234-7109fa855b0f // indirect
	golang.org/x/sys v0.0.0-20190712062909-fae7ac547cb7
	golang.org/x/tools v0.0.0-20190719005602-e377ae9d6386 // indirect
)

replace github.com/google/nftables => ../nftables
