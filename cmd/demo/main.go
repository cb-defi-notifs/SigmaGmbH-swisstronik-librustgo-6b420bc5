package main

import (
	types "github.com/SigmaGmbH/librustgo/types"
)

type MockedConnector struct{}

var _ types.Connector = MockedConnector{}

func (MockedConnector) Query([]byte) ([]byte, error) {
	return nil, nil
}

// This is just a demo to ensure we can compile a static go binary
func main() {
	// TODO: Call `create` and `call` methods
}
