package main

import (
	"errors"
	api "github.com/SigmaGmbH/librustgo/internal/api"
	types "github.com/SigmaGmbH/librustgo/types"
)

type MockedConnector struct{}

var _ types.Connector = MockedConnector{}

func (MockedConnector) Query([]byte) ([]byte, error) {
	return nil, errors.New("expected error")
}

// This is just a demo to ensure we can compile a static go binary
func main() {
	connector := MockedConnector{}
	api.Debug(connector)
}
