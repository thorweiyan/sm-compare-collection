package main

import (
	"crypto/sha256"
	"fmt"
	//"hash"
)

func main() {
	message := []byte("Test_Hash_Performance")

	sum := sha256.Sum256(message)
	fmt.Printf("%x", sum)
}
