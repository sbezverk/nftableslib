package nftableslib

import (
	"sync"

	"github.com/google/nftables"
)

// NFTables defines an interface
type NFTables interface {
	AddNFTable(name string, familyType nftables.TableFamily)
	DeleteNFTable(name string, familyType nftables.TableFamily)
	NFTableExist(name string, familyType nftables.TableFamily) bool
}

type nfTables struct {
	Conn *nftables.Conn
	sync.Mutex
	// Two dimensional map, 1st key is table family, 2nd key is table name
	tables map[nftables.TableFamily]map[string]*nfTable
}

type nfTable struct {
	table *nftables.Table
}

// InitConn initializes netlink connection of the nftables family
func InitConn(netns ...int) NFTables {
	// if netns is not specified, global namespace is used
	ts := nfTables{
		tables: map[nftables.TableFamily]map[string]*nfTable{},
	}
	if len(netns) != 0 {
		ts.Conn = &nftables.Conn{NetNS: netns[0]}
	} else {
		ts.Conn = &nftables.Conn{}
	}

	return &ts
}

// AddNFTable appends a table into NF tables list
func (nft *nfTables) AddNFTable(name string, familyType nftables.TableFamily) {
	nft.Lock()
	defer nft.Unlock()
	// Check if nf table with the same family type and name  already exists
	if _, ok := nft.tables[familyType][name]; ok {
		nft.Conn.DelTable(nft.tables[familyType][name].table)
		// Removing old table, at this point, this table should be removed from the kernel as well.
		delete(nft.tables[familyType], name)
	}
	t := nft.Conn.AddTable(&nftables.Table{
		Family: familyType,
		Name:   name,
	})
	nft.tables[familyType] = make(map[string]*nfTable)
	nft.tables[familyType][name] = &nfTable{
		table: t,
	}
}

// AddNFTable appends a table into NF tables list
func (nft *nfTables) DeleteNFTable(name string, familyType nftables.TableFamily) {
	nft.Lock()
	defer nft.Unlock()
	// Check if nf table with the same family type and name  already exists
	if _, ok := nft.tables[familyType][name]; ok {
		nft.Conn.DelTable(nft.tables[familyType][name].table)
		// Removing old table, at this point, this table should be removed from the kernel as well.
		delete(nft.tables[familyType], name)
	}
	// If no more tables exists under a specific family name, removing  family type.
	if len(nft.tables[familyType]) == 0 {
		delete(nft.tables, familyType)
	}
}

func (nft *nfTables) NFTableExist(name string, familyType nftables.TableFamily) bool {
	if _, ok := nft.tables[familyType][name]; ok {
		return true
	}
	return false
}
