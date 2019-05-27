package mock

import (
	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
)

// Interface defines methods for mock driver
type Interface interface {
	Flush() error
	FlushRuleset()
	DelTable(*nftables.Table)
	AddTable(*nftables.Table) *nftables.Table
	AddChain(*nftables.Chain) *nftables.Chain
	AddRule(*nftables.Rule) *nftables.Rule
}

// Mock defines type and methods to simulate operations with tables
type Mock struct {
	ti nftableslib.TablesInterface
}

// Flush returns
func (m *Mock) Flush() error {
	_, err := m.ti.Tables().Dump()
	if err != nil {
		return err
	}
	return nil
}

// FlushRuleset not use
func (m *Mock) FlushRuleset() {

}

// AddRule not use
func (m *Mock) AddRule(r *nftables.Rule) *nftables.Rule {
	return r
}

// DelTable not used
func (m *Mock) DelTable(t *nftables.Table) {
}

// AddTable not used
func (m *Mock) AddTable(t *nftables.Table) *nftables.Table {
	return t
}

// AddChain not used
func (m *Mock) AddChain(c *nftables.Chain) *nftables.Chain {
	return c
}

// InitMockConn initializes mock connection of the nftables family
func InitMockConn() *Mock {
	m := &Mock{}
	m.ti = nftableslib.InitNFTables(m)
	return m
}
