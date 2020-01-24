package nftableslib

import "github.com/google/nftables"

// InitConn initializes netlink connection of the nftables family
func InitConn(netns ...int) *nftables.Conn {
	// if netns is not specified, global namespace is used
	if len(netns) != 0 {
		return &nftables.Conn{NetNS: netns[0]}
	}
	return &nftables.Conn{}
}

// InitNFTables initializes netlink connection of the nftables family
func InitNFTables(conn NetNS) TablesInterface {
	// if netns is not specified, global namespace is used
	ts := nfTables{
		tables: make(map[nftables.TableFamily]map[string]*nfTable),
	}
	ts.conn = conn

	return &ts
}
