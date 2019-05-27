package nftableslib

import (
	"sync"

	"github.com/google/nftables"
)

// NetNS defines interface needed to nf tables
type NetNS interface {
	Flush() error
	FlushRuleset()
	DelTable(*nftables.Table)
	AddTable(*nftables.Table) *nftables.Table
	AddChain(*nftables.Chain) *nftables.Chain
}

// TablesInterface defines a top level interface
type TablesInterface interface {
	Tables() TableFuncs
}

// TableFuncs defines second level interface operating with nf tables
type TableFuncs interface {
	Table(name string, familyType nftables.TableFamily) ChainsInterface
	Create(name string, familyType nftables.TableFamily)
	Delete(name string, familyType nftables.TableFamily)
	Exist(name string, familyType nftables.TableFamily) bool
}

type nfTables struct {
	Conn NetNS
	sync.Mutex
	// Two dimensional map, 1st key is table family, 2nd key is table name
	tables map[nftables.TableFamily]map[string]*nfTable
}

// nfTable defines a single type/name nf table with its linked chains
type nfTable struct {
	table *nftables.Table
	ChainsInterface
}

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
		tables: map[nftables.TableFamily]map[string]*nfTable{},
	}
	ts.Conn = conn

	return &ts
}

// Tables returns methods available for managing nf tables
func (nft *nfTables) Tables() TableFuncs {
	return nft
}

// Table returns Chains Interface for a specific table
func (nft *nfTables) Table(name string, familyType nftables.TableFamily) ChainsInterface {
	nft.Lock()
	defer nft.Unlock()
	// Check if nf table with the same family type and name  already exists
	if t, ok := nft.tables[familyType][name]; ok {
		return t.ChainsInterface

	}
	// If a table does not exist, creating it and return Chains Interface to newly created table
	nft.Create(name, familyType)
	t, _ := nft.tables[familyType][name]
	return t.ChainsInterface
}

// Create appends a table into NF tables list
func (nft *nfTables) Create(name string, familyType nftables.TableFamily) {
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
		table:           t,
		ChainsInterface: newChains(nft.Conn, t),
	}

}

// Delete a specified table from NF tables list
func (nft *nfTables) Delete(name string, familyType nftables.TableFamily) {
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

// Exist checks is the table already defined
func (nft *nfTables) Exist(name string, familyType nftables.TableFamily) bool {
	if _, ok := nft.tables[familyType][name]; ok {
		return true
	}
	return false
}
