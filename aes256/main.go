package main

import (
	"./aes256"
	"fmt"
	"time"
)

func main(){
	var index int
	var key = []byte{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}
	var keystring string
	keystring = string(key[:])
	var plain = []byte{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}
	var cyphertext,origin []byte
	fmt.Printf("source message:%x\n",plain)
	fmt.Printf("key:%x\n",key)

	fmt.Println()
	fmt.Println("/******************加密*****************/")
	enc_time_start := time.Now()
	for index = 10000000 ; index>0 ; index-- {
		cyphertext,_ = aes256.Encrypt(keystring,plain)
	}
	enc_time_end := time.Now()
	fmt.Printf("enc_time:%dns\n",enc_time_end.Sub(enc_time_start).Nanoseconds()/10000000)
	fmt.Printf("cyphertest:%x\n",cyphertext)

	fmt.Println()
	fmt.Println("/******************解密*****************/")
	dec_time_start := time.Now()
	for index = 10000000 ; index>0 ; index-- {
		origin,_ = aes256.Encrypt(keystring,cyphertext)
	}
	dec_time_end := time.Now()
	fmt.Printf("dec_time:%dns\n",dec_time_end.Sub(dec_time_start).Nanoseconds()/10000000)
	fmt.Printf("origintext:%x\n",origin)
}

