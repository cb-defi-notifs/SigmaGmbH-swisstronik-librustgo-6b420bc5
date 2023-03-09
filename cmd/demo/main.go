package main

// This is just a demo to ensure we can compile a static go binary
func main() {
	db := CreateMockedDatabase()
	_ = MockedConnector{db}

	// TODO: Deploy `Counter` contract
	// TODO: Call `add` method
	// TODO: Make a query to contract to obtain current `count` value
}
