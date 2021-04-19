package types

import (
	"encoding/binary"

	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
)

// SignTxResultBytes returns sign bytes for tx result
func SignTxResultBytes(sp *tmproto.SideTxResultWithData) []byte {
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(sp.Result.Result))

	data := make([]byte, 0)
	data = append(data, bs[3]) // use last byte as result
	if len(sp.Data) > 0 {
		data = append(data, sp.Data...)
	}
	return data
}
