# wip nftableslib

nftableslib is a library offering an interface to nf tables. It is based on "github.com/google/nftables" and offers a higher level abstruction level. 
It allows to create tables, chains and rules. Once table is create a caller can request this table's Chains interface which will allow to create chains which belong to a specific table.
Similarly, once chain is create a caller can request this chain's Rules interface. 

A rule is defined by means of a Rule type. 

Rule contains parameters for a rule to configure, only L3 OR L4 parameters can be specified
```
type Rule struct {
	L3 *L3Rule
	L4 *L4Rule
}
```

A single rule can only carry L3 OR L4 parameteres. 

L4 parameters are defined by L4 type:
```
type L4Rule struct {
	L4Proto int
	Src     *Port
	Dst     *Port
	Exclude  bool
	Redirect *uint32
	Verdict  *expr.Verdict
}
```

L3 parameters are defined by L3 type:
```
type L3Rule struct {
	Src *IPAddrSpec
	Dst *IPAddrSpec
	Version *uint32
	Exclude bool
	Verdict *expr.Verdict
}
```
Rule type offers Validation method which checks all parameters provided in Rule structure for consistency.