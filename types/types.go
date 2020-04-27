package types

import (
	"encoding/json"
)

//---------- Env ---------

// Env defines the state of the blockchain environment this contract is
// running in. This must contain only trusted data - nothing from the Tx itself
// that has not been verfied (like Signer).
//
// Env are json encoded to a byte slice before passing to the wasm contract.
type Env struct {
	Block    BlockInfo    `json:"block"`
	Message  MessageInfo  `json:"message"`
	Contract ContractInfo `json:"contract"`
}

type BlockInfo struct {
	// block height this transaction is executed
	Height int64 `json:"height"`
	// time in seconds since unix epoch - since cosmwasm 0.3
	Time    int64  `json:"time"`
	ChainID string `json:"chain_id"`
}

type MessageInfo struct {
	// binary encoding of sdk.AccAddress executing the contract
	Sender CanonicalAddress `json:"sender"`
	// amount of funds send to the contract along with this message
	SentFunds []Coin `json:"sent_funds"`
}

type ContractInfo struct {
	// binary encoding of sdk.AccAddress of the contract, to be used when sending messages
	Address CanonicalAddress `json:"address"`
}

// Coin is a string representation of the sdk.Coin type (more portable than sdk.Int)
type Coin struct {
	Denom  string `json:"denom"`  // type, eg. "ATOM"
	Amount string `json:"amount"` // string encoing of decimal value, eg. "12.3456"
}

// CanoncialAddress uses standard base64 encoding, just use it as a label for developers
type CanonicalAddress = []byte

//------- Results / Msgs -------------

// CosmosResponse is the raw response from the init / handle calls
type CosmosResponse struct {
	Ok  *Result   `json:"Ok,omitempty"`
	Err *ApiError `json:"Err,omitempty"`
}

// Result defines the return value on a successful
type Result struct {
	// GasUsed is what is calculated from the VM, assuming it didn't run out of gas
	// This is set by the calling code, not the contract itself
	GasUsed uint64 `json:"gas_used"`
	// Messages comes directly from the contract and is it's request for action
	Messages []CosmosMsg `json:"messages"`
	// base64-encoded bytes to return as ABCI.Data field
	Data string `json:"data"`
	// log message to return over abci interface
	Log []LogAttribute `json:"log"`
}

// TODO: get this proper
type ApiError struct {
	ParseErr     *ParseErr `json:"ParseErr,omitempty"`
	Unauthorized *struct{} `json:"Unauthorized,omitempty"`
}

type ParseErr struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
}

// pub enum ApiError {
//     Base64Err { source: String },
//     ContractErr { msg: String },
//     DynContractErr { msg: String },
//     NotFound { kind: String },
//     NullPointer {},
//     ParseErr { kind: String, source: String },
//     SerializeErr { kind: String, source: String },
//     Unauthorized {},
//     Underflow { minuend: String, subtrahend: String },
//     // This is used for std::str::from_utf8, which we may well deprecate
//     Utf8Err { source: String },
//     // This is used for String::from_utf8, which does zero-copy from Vec<u8>, moving towards this
//     Utf8StringErr { source: String },
//     ValidationErr { field: String, msg: String },
// }

// LogAttribute
type LogAttribute struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// CosmosMsg is an rust enum and only (exactly) one of the fields should be set
// Should we do a cleaner approach in Go? (type/data?)
type CosmosMsg struct {
	Bank   *BankMsg        `json:"bank,omitempty"`
	Custom json.RawMessage `json:"custom,omitempty"`
	// 	Staking *StakingMsg `json:"staking,omitempty"`
	Wasm *WasmMsg `json:"wasm,omitempty"`
}

type BankMsg struct {
	Send *SendMsg `json:"send,omitempty"`
}

// SendMsg contains instructions for a Cosmos-SDK/SendMsg
// It has a fixed interface here and should be converted into the proper SDK format before dispatching
type SendMsg struct {
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
	Amount      []Coin `json:"amount"`
}

type WasmMsg struct {
	Execute     *ExecuteMsg     `json:"execute,omitempty"`
	Instantiate *InstantiateMsg `json:"instantiate,omitempty"`
}

// ExecuteMsg is used to call another defined contract on this chain.
// The calling contract requires the callee to be defined beforehand,
// and the address should have been defined in initialization.
// And we assume the developer tested the ABIs and coded them together.
//
// Since a contract is immutable once it is deployed, we don't need to transform this.
// If it was properly coded and worked once, it will continue to work throughout upgrades.
type ExecuteMsg struct {
	// ContractAddr is the sdk.AccAddress of the contract, which uniquely defines
	// the contract ID and instance ID. The sdk module should maintain a reverse lookup table.
	ContractAddr string `json:"contract_addr"`
	// Msg is assumed to be a json-encoded message, which will be passed directly
	// as `userMsg` when calling `Handle` on the above-defined contract
	Msg []byte `json:"msg"`
	// Send is an optional amount of coins this contract sends to the called contract
	Send []Coin `json:"send"`
}

type InstantiateMsg struct {
	// CodeID is the reference to the wasm byte code as used by the Cosmos-SDK
	CodeID uint64 `json:"code_id"`
	// Msg is assumed to be a json-encoded message, which will be passed directly
	// as `userMsg` when calling `Handle` on the above-defined contract
	Msg []byte `json:"msg"`
	// Send is an optional amount of coins this contract sends to the called contract
	Send []Coin `json:"send"`
}

//-------- Queries --------

type QueryResponse struct {
	Ok  []byte    `json:"Ok,omitempty"`
	Err *ApiError `json:"Err,omitempty"`
}
