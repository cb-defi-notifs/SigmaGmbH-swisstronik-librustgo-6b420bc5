package librustgo

import (
	"encoding/json"
	"testing"

	"github.com/SigmaGmbH/librustgo/internal/api"
	"github.com/SigmaGmbH/librustgo/types"
	"github.com/stretchr/testify/require"
)

const IBC_TEST_CONTRACT = "./testdata/ibc_reflect.wasm"

// IBCInstantiateMsg is the Go version of
// https://github.com/CosmWasm/cosmwasm/blob/v0.14.0-beta1/contracts/ibc-reflect/src/msg.rs#L9-L11
type IBCInstantiateMsg struct {
	ReflectCodeID uint64 `json:"reflect_code_id"`
}

// IBCExecuteMsg is the Go version of
// https://github.com/CosmWasm/cosmwasm/blob/v0.14.0-beta1/contracts/ibc-reflect/src/msg.rs#L15
type IBCExecuteMsg struct {
	InitCallback InitCallback `json:"init_callback"`
}

// InitCallback is the Go version of
// https://github.com/CosmWasm/cosmwasm/blob/v0.14.0-beta1/contracts/ibc-reflect/src/msg.rs#L17-L22
type InitCallback struct {
	ID           string `json:"id"`
	ContractAddr string `json:"contract_addr"`
}

type IBCPacketMsg struct {
	Dispatch *DispatchMsg `json:"dispatch,omitempty"`
}

type DispatchMsg struct {
	Msgs []types.CosmosMsg `json:"msgs"`
}

type IBCQueryMsg struct {
	ListAccounts *struct{} `json:"list_accounts,omitempty"`
}

type ListAccountsResponse struct {
	Accounts []AccountInfo `json:"accounts"`
}

type AccountInfo struct {
	Account   string `json:"account"`
	ChannelID string `json:"channel_id"`
}

// We just check if an error is returned or not
type AcknowledgeDispatch struct {
	Err string `json:"error"`
}

func toBytes(t *testing.T, v interface{}) []byte {
	bz, err := json.Marshal(v)
	require.NoError(t, err)
	return bz
}

const IBC_VERSION = "ibc-reflect-v1"

func TestIBCMsgGetChannel(t *testing.T) {
	const CHANNEL_ID = "channel-432"

	msg1 := api.MockIBCChannelOpenInit(CHANNEL_ID, types.Ordered, "random-garbage")
	msg2 := api.MockIBCChannelOpenTry(CHANNEL_ID, types.Ordered, "random-garbage")
	msg3 := api.MockIBCChannelConnectAck(CHANNEL_ID, types.Ordered, "random-garbage")
	msg4 := api.MockIBCChannelConnectConfirm(CHANNEL_ID, types.Ordered, "random-garbage")
	msg5 := api.MockIBCChannelCloseInit(CHANNEL_ID, types.Ordered, "random-garbage")
	msg6 := api.MockIBCChannelCloseConfirm(CHANNEL_ID, types.Ordered, "random-garbage")

	require.Equal(t, msg1.GetChannel(), msg2.GetChannel())
	require.Equal(t, msg1.GetChannel(), msg3.GetChannel())
	require.Equal(t, msg1.GetChannel(), msg4.GetChannel())
	require.Equal(t, msg1.GetChannel(), msg5.GetChannel())
	require.Equal(t, msg1.GetChannel(), msg6.GetChannel())
	require.Equal(t, msg1.GetChannel().Endpoint.ChannelID, CHANNEL_ID)
}

func TestIBCMsgGetCounterVersion(t *testing.T) {
	const CHANNEL_ID = "channel-432"
	const VERSION = "random-garbage"

	msg1 := api.MockIBCChannelOpenInit(CHANNEL_ID, types.Ordered, VERSION)
	v, ok := msg1.GetCounterVersion()
	require.False(t, ok)

	msg2 := api.MockIBCChannelOpenTry(CHANNEL_ID, types.Ordered, VERSION)
	v, ok = msg2.GetCounterVersion()
	require.True(t, ok)
	require.Equal(t, VERSION, v)

	msg3 := api.MockIBCChannelConnectAck(CHANNEL_ID, types.Ordered, VERSION)
	v, ok = msg3.GetCounterVersion()
	require.True(t, ok)
	require.Equal(t, VERSION, v)

	msg4 := api.MockIBCChannelConnectConfirm(CHANNEL_ID, types.Ordered, VERSION)
	v, ok = msg4.GetCounterVersion()
	require.False(t, ok)
}
