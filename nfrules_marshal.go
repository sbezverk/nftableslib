package nftableslib

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func (nfr *nfRule) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, '[')

	for i := 0; i < len(nfr.rule.Exprs); i++ {
		e, err := marshalExpression(nfr.rule.Exprs[i])
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, e...)
		if i < len(nfr.rule.Exprs)-1 {
			jsonData = append(jsonData, ',')
		}
	}
	jsonData = append(jsonData, ']')

	return jsonData, nil
}

func marshalExpression(exp expr.Any) ([]byte, error) {
	var b []byte

	if e, ok := exp.(*expr.Meta); ok {
		b = append(b, []byte("{\"Key\":")...)
		switch e.Key {
		case expr.MetaKeyLEN:
			b = append(b, []byte("\"expr.MetaKeyLEN\"")...)
		case expr.MetaKeyPROTOCOL:
			b = append(b, []byte("\"expr.MetaKeyPROTOCOL\"")...)
		case expr.MetaKeyPRIORITY:
			b = append(b, []byte("\"expr.MetaKeyPRIORITY\"")...)
		case expr.MetaKeyMARK:
			b = append(b, []byte("\"expr.MetaKeyMARK\"")...)
		case expr.MetaKeyIIF:
			b = append(b, []byte("\"expr.MetaKeyIIF\"")...)
		case expr.MetaKeyOIF:
			b = append(b, []byte("\"expr.MetaKeyOIF\"")...)
		case expr.MetaKeyIIFNAME:
			b = append(b, []byte("\"expr.MetaKeyIIFNAME\"")...)
		case expr.MetaKeyOIFNAME:
			b = append(b, []byte("\"expr.MetaKeyOIFNAME\"")...)
		case expr.MetaKeyIIFTYPE:
			b = append(b, []byte("\"expr.MetaKeyIIFTYPE\"")...)
		case expr.MetaKeyOIFTYPE:
			b = append(b, []byte("\"expr.MetaKeyOIFTYPE\"")...)
		case expr.MetaKeySKUID:
			b = append(b, []byte("\"expr.MetaKeySKUID\"")...)
		case expr.MetaKeySKGID:
			b = append(b, []byte("\"expr.MetaKeySKGID\"")...)
		case expr.MetaKeyNFTRACE:
			b = append(b, []byte("\"expr.MetaKeyNFTRACE\"")...)
		case expr.MetaKeyRTCLASSID:
			b = append(b, []byte("\"expr.MetaKeyRTCLASSID\"")...)
		case expr.MetaKeySECMARK:
			b = append(b, []byte("\"expr.MetaKeySECMARK\"")...)
		case expr.MetaKeyNFPROTO:
			b = append(b, []byte("\"expr.MetaKeyNFPROTO\"")...)
		case expr.MetaKeyL4PROTO:
			b = append(b, []byte("\"expr.MetaKeyL4PROTO\"")...)
		case expr.MetaKeyBRIIIFNAME:
			b = append(b, []byte("\"expr.MetaKeyBRIIIFNAME\"")...)
		case expr.MetaKeyBRIOIFNAME:
			b = append(b, []byte("\"expr.MetaKeyBRIOIFNAME\"")...)
		case expr.MetaKeyPKTTYPE:
			b = append(b, []byte("\"expr.MetaKeyPKTTYPE\"")...)
		case expr.MetaKeyCPU:
			b = append(b, []byte("\"expr.MetaKeyCPU\"")...)
		case expr.MetaKeyIIFGROUP:
			b = append(b, []byte("\"expr.MetaKeyIIFGROUP\"")...)
		case expr.MetaKeyOIFGROUP:
			b = append(b, []byte("\"expr.MetaKeyOIFGROUP\"")...)
		case expr.MetaKeyCGROUP:
			b = append(b, []byte("\"expr.MetaKeyCGROUP\"")...)
		case expr.MetaKeyPRANDOM:
			b = append(b, []byte("\"expr.MetaKeyPRANDOM\"")...)
		default:
			b = append(b, []byte("\"Unknown key\"")...)
		}
		b = append(b, []byte(",\"Register\":")...)
		b = append(b, []byte(fmt.Sprintf("%d}", e.Register))...)

		return b, nil
	}
	if e, ok := exp.(*expr.Cmp); ok {
		b = append(b, []byte("{\"Op\":")...)
		switch e.Op {
		case expr.CmpOpEq:
			b = append(b, []byte("\"expr.CmpOpEq\"")...)
		case expr.CmpOpNeq:
			b = append(b, []byte("\"expr.CmpOpNeq\"")...)
		case expr.CmpOpLt:
			b = append(b, []byte("\"expr.CmpOpLt\"")...)
		case expr.CmpOpLte:
			b = append(b, []byte("\"expr.CmpOpLte\"")...)
		case expr.CmpOpGt:
			b = append(b, []byte("\"expr.CmpOpGt\"")...)
		case expr.CmpOpGte:
			b = append(b, []byte("\"expr.CmpOpGte\"")...)
		default:
			b = append(b, []byte("\"Unknown Op\"")...)
		}
		b = append(b, []byte(",\"Register\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.Register))...)

		b = append(b, []byte(",\"Data\":")...)
		b = append(b, '[')
		for i := 0; i < len(e.Data); i++ {
			b = append(b, fmt.Sprintf("\"%#x\"", e.Data[i])...)
			if i < len(e.Data)-1 {
				b = append(b, ',')
			}
		}
		b = append(b, ']')
		b = append(b, '}')
		return b, nil
	}
	if e, ok := exp.(*expr.Payload); ok {
		b = append(b, []byte("{\"DestRegister\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.DestRegister))...)
		b = append(b, []byte(",\"Base\":")...)
		switch e.Base {
		case expr.PayloadBaseLLHeader:
			b = append(b, []byte("\"expr.PayloadBaseLLHeader\"")...)
		case expr.PayloadBaseNetworkHeader:
			b = append(b, []byte("\"expr.PayloadBaseNetworkHeader\"")...)
		case expr.PayloadBaseTransportHeader:
			b = append(b, []byte("\"expr.PayloadBaseTransportHeader\"")...)
		default:
			b = append(b, []byte("\"Unknown Base\"")...)
		}
		b = append(b, []byte(",\"Len\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.Len))...)
		b = append(b, []byte(",\"Offset\":")...)
		b = append(b, []byte(fmt.Sprintf("%d}", e.Offset))...)
		return b, nil
	}
	if e, ok := exp.(*expr.Immediate); ok {
		b = append(b, []byte("{\"Register\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.Register))...)
		b = append(b, []byte(",\"Data\":")...)
		b = append(b, '[')
		for i := 0; i < len(e.Data); i++ {
			b = append(b, fmt.Sprintf("\"%#x\"", e.Data[i])...)
			if i < len(e.Data)-1 {
				b = append(b, ',')
			}
		}
		b = append(b, ']')
		b = append(b, '}')
		return b, nil
	}
	if e, ok := exp.(*expr.Verdict); ok {
		b = append(b, []byte("{\"Kind\":")...)
		b = append(b, []byte(fmt.Sprintf("\"%#x\"", uint32(e.Kind)))...)
		if e.Chain != "" {
			b = append(b, []byte(",\"Chain\":")...)
			b = append(b, []byte(fmt.Sprintf("\"%s\"", e.Chain))...)
		}
		b = append(b, []byte("}")...)
		return b, nil
	}
	if e, ok := exp.(*expr.Redir); ok {
		b = append(b, []byte("{\"RegisterProtoMin\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.RegisterProtoMin))...)
		b = append(b, []byte(",\"RegisterProtoMax\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.RegisterProtoMax))...)
		b = append(b, []byte(",\"Flags\":")...)
		b = append(b, []byte(fmt.Sprintf("\"%#x\"}", e.Flags))...)
		return b, nil
	}
	if e, ok := exp.(*expr.TProxy); ok {
		b = append(b, []byte("{\"Family\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.Family))...)
		b = append(b, []byte(",\"TableFamily\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.TableFamily))...)
		b = append(b, []byte(",\"RegPort\":")...)
		b = append(b, []byte(fmt.Sprintf("\"%#x\"}", e.RegPort))...)
		return b, nil
	}
	if e, ok := exp.(*expr.Lookup); ok {
		b = append(b, []byte("{\"SourceRegister\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.SourceRegister))...)
		b = append(b, []byte(",\"DestRegister\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.DestRegister))...)
		b = append(b, []byte(",\"SetID\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.SetID))...)
		b = append(b, []byte(",\"SetName\":")...)
		b = append(b, []byte(fmt.Sprintf("\"%s\"", e.SetName))...)
		b = append(b, []byte(",\"Invert\":")...)
		b = append(b, []byte(fmt.Sprintf("\"%t\"}", e.Invert))...)
		return b, nil
	}
	if e, ok := exp.(*expr.Range); ok {
		b = append(b, []byte("{\"Register\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.Register))...)
		b = append(b, []byte(",\"Op\":")...)
		switch e.Op {
		case expr.CmpOpEq:
			b = append(b, []byte("\"expr.CmpOpEq\"")...)
		case expr.CmpOpNeq:
			b = append(b, []byte("\"expr.CmpOpNeq\"")...)
		case expr.CmpOpLt:
			b = append(b, []byte("\"expr.CmpOpLt\"")...)
		case expr.CmpOpLte:
			b = append(b, []byte("\"expr.CmpOpLte\"")...)
		case expr.CmpOpGt:
			b = append(b, []byte("\"expr.CmpOpGt\"")...)
		case expr.CmpOpGte:
			b = append(b, []byte("\"expr.CmpOpGte\"")...)
		default:
			b = append(b, []byte("\"Unknown Op\"")...)
		}

		b = append(b, []byte(",\"FromData\":")...)
		b = append(b, '[')
		for i := 0; i < len(e.FromData); i++ {
			b = append(b, fmt.Sprintf("\"%#x\"", e.FromData[i])...)
			if i < len(e.FromData)-1 {
				b = append(b, ',')
			}
		}
		b = append(b, ']')
		b = append(b, []byte(",\"ToData\":")...)
		b = append(b, '[')
		for i := 0; i < len(e.ToData); i++ {
			b = append(b, fmt.Sprintf("\"%#x\"", e.ToData[i])...)
			if i < len(e.ToData)-1 {
				b = append(b, ',')
			}
		}
		b = append(b, ']')
		b = append(b, '}')
		return b, nil
	}

	if e, ok := exp.(*expr.Bitwise); ok {
		b = append(b, []byte("{\"SourceRegister\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.SourceRegister))...)
		b = append(b, []byte(",\"DestRegister\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.DestRegister))...)
		b = append(b, []byte(",\"Len\":")...)
		b = append(b, []byte(fmt.Sprintf("%d", e.Len))...)
		b = append(b, []byte(",\"Mask\":")...)
		b = append(b, '[')
		for i := 0; i < len(e.Mask); i++ {
			b = append(b, fmt.Sprintf("\"%#x\"", e.Mask[i])...)
			if i < len(e.Mask)-1 {
				b = append(b, ',')
			}
		}
		b = append(b, ']')
		b = append(b, []byte(",\"Xor\":")...)
		b = append(b, '[')
		for i := 0; i < len(e.Xor); i++ {
			b = append(b, fmt.Sprintf("\"%#x\"", e.Xor[i])...)
			if i < len(e.Xor)-1 {
				b = append(b, ',')
			}
		}
		b = append(b, ']')
		b = append(b, '}')
		return b, nil
	}
	/*
		TODO: (sbezverk)
			expr.Masq:
			expr.NAT:
			expr.Objref:
			expr.Queue:
			expr.Rt:
	*/

	return nil, fmt.Errorf("unknown expression type %T", exp)
}
