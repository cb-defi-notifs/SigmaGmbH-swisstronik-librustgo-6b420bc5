package api_test

import "testing"
import "github.com/SigmaGmbH/librustgo/internal/api"

func TestDebugCall(t *testing.T) {
	api.MakeDebugRequest()
}
