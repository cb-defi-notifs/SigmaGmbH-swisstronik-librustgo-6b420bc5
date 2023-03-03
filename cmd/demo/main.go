package main

import (
	"errors"
	api "github.com/SigmaGmbH/librustgo/internal/api"
	types "github.com/SigmaGmbH/librustgo/types"
)

type MockedQueryHandler struct{}

var _ types.DataQuerier = MockedQueryHandler{}

func (MockedQueryHandler) Query([]byte) ([]byte, error) {
	return nil, errors.New("expected error")
}

// This is just a demo to ensure we can compile a static go binary
func main() {
	querier := MockedQueryHandler{}
	api.Debug(querier)
}
