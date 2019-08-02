package nftableslib

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/google/nftables"
)

// NetNS defines interface needed to nf tables
type NetNS interface {
	Flush() error
	FlushRuleset()
	DelTable(*nftables.Table)
	DelChain(*nftables.Chain)
	AddTable(*nftables.Table) *nftables.Table
	AddChain(*nftables.Chain) *nftables.Chain
	AddRule(*nftables.Rule) *nftables.Rule
	DelRule(*nftables.Rule) error
	AddSet(*nftables.Set, []nftables.SetElement) error
	GetRuleHandle(t *nftables.Table, c *nftables.Chain, ruleID uint32) (uint64, error)
}

// TablesInterface defines a top level interface
type TablesInterface interface {
	Tables() TableFuncs
}

// TableFuncs defines second level interface operating with nf tables
type TableFuncs interface {
	Table(name string, familyType nftables.TableFamily) (ChainsInterface, error)
	Create(name string, familyType nftables.TableFamily) error
	Delete(name string, familyType nftables.TableFamily) error
	CreateImm(name string, familyType nftables.TableFamily) error
	DeleteImm(name string, familyType nftables.TableFamily) error
	Exist(name string, familyType nftables.TableFamily) bool
	Dump() ([]byte, error)
}

type nfTables struct {
	conn NetNS
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
	ts.conn = conn

	return &ts
}

// Tables returns methods available for managing nf tables
func (nft *nfTables) Tables() TableFuncs {
	return nft
}

// Table returns Chains Interface for a specific table
func (nft *nfTables) Table(name string, familyType nftables.TableFamily) (ChainsInterface, error) {
	nft.Lock()
	defer nft.Unlock()
	// Check if nf table with the same family type and name  already exists
	if t, ok := nft.tables[familyType][name]; ok {
		return t.ChainsInterface, nil

	}

	return nil, fmt.Errorf("table %s of type %v does not exist", name, familyType)
}

// Create appends a table into NF tables list
func (nft *nfTables) Create(name string, familyType nftables.TableFamily) error {
	nft.Lock()
	defer nft.Unlock()
	// Check if nf table with the same family type and name  already exists
	if _, ok := nft.tables[familyType][name]; ok {
		return fmt.Errorf("table %s of type %+v already exists", name, familyType)
		//		nft.Conn.DelTable(nft.tables[familyType][name].table)
		// Removing old table, at this point, this table should be removed from the kernel as well.
		//		delete(nft.tables[familyType], name)
	}
	t := nft.conn.AddTable(&nftables.Table{
		Family: familyType,
		Name:   name,
	})
	nft.tables[familyType] = make(map[string]*nfTable)
	nft.tables[familyType][name] = &nfTable{
		table:           t,
		ChainsInterface: newChains(nft.conn, t),
	}
	return nil
}

// Create appends a table into NF tables list and request to program it immediately
func (nft *nfTables) CreateImm(name string, familyType nftables.TableFamily) error {
	if err := nft.Create(name, familyType); err != nil {
		return err
	}

	return nft.conn.Flush()
}

// DeleteImm requests nftables module to remove a specified table from the kernel and from NF tables list
func (nft *nfTables) DeleteImm(name string, familyType nftables.TableFamily) error {
	if err := nft.Delete(name, familyType); err != nil {
		return err
	}

	return nft.conn.Flush()
}

// Delete removes a specified table from NF tables list
func (nft *nfTables) Delete(name string, familyType nftables.TableFamily) error {
	nft.Lock()
	defer nft.Unlock()
	// Check if nf table with the same family type and name  already exists
	if _, ok := nft.tables[familyType][name]; ok {
		nft.conn.DelTable(nft.tables[familyType][name].table)
		// Removing old table, at this point, this table should be removed from the kernel as well.
		delete(nft.tables[familyType], name)
	}
	// If no more tables exists under a specific family name, removing  family type.
	if len(nft.tables[familyType]) == 0 {
		delete(nft.tables, familyType)
	}

	return nil
}

// Exist checks is the table already defined
func (nft *nfTables) Exist(name string, familyType nftables.TableFamily) bool {
	if _, ok := nft.tables[familyType][name]; ok {
		return true
	}
	return false
}

// Dump outputs json representation of all defined tables/chains/rules
func (nft *nfTables) Dump() ([]byte, error) {
	nft.Lock()
	defer nft.Unlock()
	var data []byte

	for _, f := range nft.tables {
		for _, t := range f {
			if b, err := json.Marshal(&t.table); err != nil {
				return nil, err
			} else {
				data = append(data, b...)
			}
			if b, err := t.Chains().Dump(); err != nil {
				return nil, err
			} else {
				data = append(data, b...)
			}
		}
	}

	return data, nil
}

func printTable(t *nftables.Table) []byte {
	return []byte(fmt.Sprintf("\nTable: %s Family: %+v Flags: %x Use: %x \n", t.Name, t.Family, t.Flags, t.Use))
}

// IsNFTablesOn detects whether nf_tables module is loaded or not, it return true is ListChains call succeeds,
// otherwise it return false.
func IsNFTablesOn() bool {
	conn := InitConn()
	if _, err := conn.ListChains(); err != nil {
		return false
	}
	return true
}
