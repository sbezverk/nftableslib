package main

import (
	"fmt"
	"os"

	"github.com/sbezverk/nftableslib/e2e/setenv"
)

func main() {
	t, err := setenv.NewP2PTestEnv("1.1.1.1", "1.1.1.2")
	if err != nil {
		fmt.Printf("Failed with error: %+v\n", err)
		os.Exit(1)
	}
	t.Cleanup()
}
