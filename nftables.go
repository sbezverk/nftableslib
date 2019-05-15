package nftableslib

import (
	"sync"

	"github.com/google/nftables"
)

// NFTables defines an interface
type NFTables interface {
	AddNFTable(name string, familyType nftables.TableFamily)
	NFTableExistAndProgrammed(name string, familyType nftables.TableFamily) (bool, bool)
}

type nfTables struct {
	Conn *nftables.Conn
	sync.Mutex
	// Two dimensional map, 1st key is table family, 2nd key is table name
	tables map[nftables.TableFamily]map[string]*nfTable
}

type nfTable struct {
	table      *nftables.Table
	programmed bool
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
	if t, ok := nft.tables[familyType][name]; ok {
		if t.programmed {
			// TODO Figure out what to do if a table with specified type and name already exists.
			// Should the corresponding kernel table be deleted first?
		}
		// Removing old table, at this point, this table should be removed from the kernel as well.
		delete(nft.tables[familyType], name)
	}
	t := nft.Conn.AddTable(&nftables.Table{
		Family: familyType,
		Name:   name,
	})
	nft.tables[familyType] = make(map[string]*nfTable)
	nft.tables[familyType][name] = &nfTable{
		table:      t,
		programmed: false,
	}
}

func (nft *nfTables) NFTableExistAndProgrammed(name string, familyType nftables.TableFamily) (bool, bool) {
	if t, ok := nft.tables[familyType][name]; ok {
		if t.programmed {
			return true, true
		}
		return true, false
	}
	return false, false
}
