package main

import (
	"crypto/sha256"
	"fmt"
	//"hash"
	"time"
)

func main() {
	testsha256 := sha256.New()
	//sum := sha256.Sum256([]byte("hello world\n"))
	var index int
	var output []byte
	message := []byte("Test_Hash_Performance")
	var message2 = []byte("Test_Hash_PerformanceTest_Hash_PerformanceTest_Hash_PerformanceTest_Hash_Performance")
	var message3 = []byte("Test_Hash_PerformanceTest_Hash_PerformanceTest_Hash_PerformanceTest_Hash_PerformanceTest_Hash_PerformanceTest_Hash_PerformanceTest_Hash_PerformanceTest_Hash_PerformanceTest_Hash_PerformanceTest_Hash_PerformanceTest_Hash_PerformanceTest_Hash_PerformanceTest_Hash_PerformanceTest_Hash_PerformanceTest_Hash_PerformanceTest_Hash_Performance")
	fmt.Printf("source message:%s\n", message)

	fmt.Println()
	fmt.Println("/******************256bit*****************/")
	hash_time_start := time.Now()
	for index = 100000; index > 0; index-- {
		testsha256.Write(message)
		output = testsha256.Sum(nil)
	}
	hash_time_end := time.Now()
	fmt.Printf("Hash_time:%dns\n", hash_time_end.Sub(hash_time_start).Nanoseconds()/100000)
	fmt.Printf("cyphertest:%x\n", output)

	hash_time_start = time.Now()
	for index = 100000; index > 0; index-- {
		testsha256.Write(message2)
		output = testsha256.Sum(nil)
	}
	hash_time_end = time.Now()
	fmt.Printf("Hash_time:%dns(4 times length)\n", hash_time_end.Sub(hash_time_start).Nanoseconds()/100000)

	hash_time_start = time.Now()
	for index = 100000; index > 0; index-- {
		testsha256.Write(message3)
		output = testsha256.Sum(nil)
	}
	hash_time_end = time.Now()
	fmt.Printf("Hash_time:%dns(16 times length)\n", hash_time_end.Sub(hash_time_start).Nanoseconds()/100000)

}
