package nftableslib

import (
	"github.com/google/nftables/expr"
)

/*
	List of available keys:

    MetaKeyLEN        MetaKey = unix.NFT_META_LEN
    MetaKeyPROTOCOL   MetaKey = unix.NFT_META_PROTOCOL
    MetaKeyPRIORITY   MetaKey = unix.NFT_META_PRIORITY
    MetaKeyMARK       MetaKey = unix.NFT_META_MARK
    MetaKeyIIF        MetaKey = unix.NFT_META_IIF
    MetaKeyOIF        MetaKey = unix.NFT_META_OIF
    MetaKeyIIFNAME    MetaKey = unix.NFT_META_IIFNAME
    MetaKeyOIFNAME    MetaKey = unix.NFT_META_OIFNAME
    MetaKeyIIFTYPE    MetaKey = unix.NFT_META_IIFTYPE
    MetaKeyOIFTYPE    MetaKey = unix.NFT_META_OIFTYPE
    MetaKeySKUID      MetaKey = unix.NFT_META_SKUID
    MetaKeySKGID      MetaKey = unix.NFT_META_SKGID
    MetaKeyNFTRACE    MetaKey = unix.NFT_META_NFTRACE
    MetaKeyRTCLASSID  MetaKey = unix.NFT_META_RTCLASSID
    MetaKeySECMARK    MetaKey = unix.NFT_META_SECMARK
    MetaKeyNFPROTO    MetaKey = unix.NFT_META_NFPROTO
    MetaKeyL4PROTO    MetaKey = unix.NFT_META_L4PROTO
    MetaKeyBRIIIFNAME MetaKey = unix.NFT_META_BRI_IIFNAME
    MetaKeyBRIOIFNAME MetaKey = unix.NFT_META_BRI_OIFNAME
    MetaKeyPKTTYPE    MetaKey = unix.NFT_META_PKTTYPE
    MetaKeyCPU        MetaKey = unix.NFT_META_CPU
    MetaKeyIIFGROUP   MetaKey = unix.NFT_META_IIFGROUP
    MetaKeyOIFGROUP   MetaKey = unix.NFT_META_OIFGROUP
    MetaKeyCGROUP     MetaKey = unix.NFT_META_CGROUP
    MetaKeyPRANDOM    MetaKey = unix.NFT_META_PRANDOM
*/

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

func inputIntfByName(intf string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(intf),
		},
	}
}

func outputIntfByName(intf string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(intf),
		},
	}
}
