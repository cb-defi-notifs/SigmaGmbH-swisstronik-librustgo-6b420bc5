package main

import (
	"encoding/hex"
	"errors"
	"github.com/hashicorp/go-memdb"
)

type Account struct {
	Address []byte // 20-bytes address
	Balance []byte // big-endian encoded Uint256 balance
	Nonce   uint64
	Code    []byte            // Contract code. Is nil if account is not a contract
	State   map[string][]byte // Contains state of the contract. Empty if account is not a contract
}

type MockedDB struct {
	db *memdb.MemDB
}

// CreateMockedDatabase creates an in-memory database that is used to keep changes between SGXVM execution on a Go side
func CreateMockedDatabase() MockedDB {
	schema := &memdb.DBSchema{
		Tables: map[string]*memdb.TableSchema{
			"account": &memdb.TableSchema{
				Name: "account",
				Indexes: map[string]*memdb.IndexSchema{
					"id": &memdb.IndexSchema{
						Name:    "Address",
						Unique:  true,
						Indexer: &memdb.StringFieldIndex{Field: "Address"},
					},
				},
			},
		},
	}

	db, err := memdb.NewMemDB(schema)
	if err != nil {
		panic(err) // We do not handle this error since this code is used only for testing
	}

	return MockedDB{db}
}

// GetAccount returns account struct stored in database
func (m MockedDB) GetAccount(address []byte) (*Account, error) {
	txn := m.db.Txn(false)
	defer txn.Abort()

	raw, err := txn.First("account", "id", address)
	if err != nil {
		return &Account{}, err
	}

	return raw.(*Account), nil
}

// GetAccountOrEmpty returns found account or account with empty fields
func (m MockedDB) GetAccountOrEmpty(address []byte) (Account, error) {
	acct, err := m.GetAccount(address)

	if err != nil {
		return Account{}, err
	}

	if acct == nil {
		return Account{
			Address: address,
			Balance: make([]byte, 32),
			Nonce:   0,
			Code:    nil,
			State:   nil,
		}, nil
	}

	return Account{
		Address: acct.Address,
		Balance: acct.Balance,
		Nonce:   acct.Nonce,
		Code:    acct.Code,
		State:   acct.State,
	}, nil
}

// InsertAccount inserts new account with balance and nonce fields
func (m MockedDB) InsertAccount(address []byte, balance []byte, nonce uint64) error {
	txn := m.db.Txn(true)
	acct := Account{
		Address: address,
		Balance: balance,
		Nonce:   nonce,
	}

	if err := txn.Insert("account", acct); err != nil {
		return err
	}

	txn.Commit()
	return nil
}

// InsertContractCode inserts code of the contract
func (m MockedDB) InsertContractCode(address []byte, code []byte) error {
	acct, err := m.GetAccount(address)
	if err != nil {
		return err
	}

	if acct == nil {
		return errors.New("cannot insert contract code. Account not found")
	}

	txn := m.db.Txn(true)
	updatedAcct := Account{
		Address: acct.Address,
		Balance: acct.Balance,
		Nonce:   acct.Nonce,
		Code:    code,
		State:   acct.State,
	}
	if err := txn.Insert("account", updatedAcct); err != nil {
		return err
	}
	txn.Commit()
	return nil
}

// InsertStorageCell inserts new storage cell
func (m MockedDB) InsertStorageCell(address []byte, key []byte, value []byte) error {
	acct, err := m.GetAccount(address)
	if err != nil {
		return err
	}

	if acct == nil {
		return errors.New("cannot insert contract code. Account not found")
	}

	txn := m.db.Txn(true)

	hexKey := hex.EncodeToString(key)
	var stateMap = acct.State
	if stateMap == nil {
		stateMap = make(map[string][]byte)
	}
	stateMap[hexKey] = value

	updatedAcct := Account{
		Address: acct.Address,
		Balance: acct.Balance,
		Nonce:   acct.Nonce,
		Code:    acct.Code,
		State:   stateMap,
	}
	if err := txn.Insert("account", updatedAcct); err != nil {
		return err
	}
	txn.Commit()
	return nil
}

// GetStorageCell returns value contained in the storage cell
func (m MockedDB) GetStorageCell(address []byte, key []byte) ([]byte, error) {
	acct, err := m.GetAccount(address)
	if err != nil {
		return nil, err
	}

	if acct == nil {
		// If account was not found, return default value (32 zero bytes)
		return make([]byte, 32), nil
	}

	hexKey := hex.EncodeToString(key)
	value, found := acct.State[hexKey]

	if !found {
		// If account was not found, return default value (32 zero bytes)
		return make([]byte, 32), nil
	}

	return value, nil
}

// Contains checks if provided address presents in DB
func (m MockedDB) Contains(address []byte) (bool, error) {
	acct, err := m.GetAccount(address)
	if err != nil {
		return false, err
	}

	return acct != nil, nil
}

// Delete removes account record from the database
func (m MockedDB) Delete(address []byte) error {
	txn := m.db.Txn(true)
	return txn.Delete("account", Account{Address: address})
}
