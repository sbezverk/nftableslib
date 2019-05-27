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
}

type mock struct {
}

func (m *mock) Flush() error {
	return nil
}

func (m *mock) FlushRuleset() {

}

func (m *mock) DelTable(t *nftables.Table) {

}
func (m *mock) AddTable(t *nftables.Table) *nftables.Table {
	return &nftables.Table{}
}
func (m *mock) AddChain(c *nftables.Chain) *nftables.Chain {
	return &nftables.Chain{}
}

// InitMockConn initializes mock connection of the nftables family
func InitMockConn() nftableslib.TablesInterface {
	return nftableslib.InitNFTables(&mock{})
}
