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
	AddSet(*nftables.Set, []nftables.SetElement) error
	GetRuleHandle(t *nftables.Table, c *nftables.Chain, ruleID uint32) (uint64, error)
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

// DelChain not used
func (m *Mock) DelChain(c *nftables.Chain) {
}

// AddSet not used
func (m *Mock) AddSet(s *nftables.Set, se []nftables.SetElement) error {
	return nil
}

// GetRuleHandle not used
func (m *Mock) GetRuleHandle(t *nftables.Table, c *nftables.Chain, ruleID uint32) (uint64, error) {
	return 0, nil
}

// InitMockConn initializes mock connection of the nftables family
func InitMockConn() *Mock {
	m := &Mock{}
	m.ti = nftableslib.InitNFTables(m)
	return m
}
