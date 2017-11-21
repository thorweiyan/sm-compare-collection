package main

import (
	//"io"
	"crypto/sha512"
	"./edwards25519"
	"time"
	"fmt"
	"./ed25519"
)


func main(){
	var PriKey = [ed25519.PrivateKeySize]byte{0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 0xc5, 0xb8}
	publicKey := new([32]byte)

	h := sha512.New()
	h.Write(PriKey[:32])
	digest := h.Sum(nil)

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var A edwards25519.ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], digest)
	edwards25519.GeScalarMultBase(&A, &hBytes)
	A.ToBytes(publicKey)

	copy(PriKey[32:], publicKey[:])
	var Sig_Msg = []byte("Sign_Test_Message")
	var Sig_Msg2 = []byte("Sign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_Message")
	var Sig_Msg3 = []byte("Sign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_Message")
	var sig,sig2,sig3 *[ed25519.SignatureSize]byte
	var index int
	//var x bool
	sm2_sig_start := time.Now()
	for index=100000;index>0;index-- {
		sig = ed25519.Sign(&PriKey, Sig_Msg)
	}
	sm2_sig_end := time.Now()
	fmt.Printf("Sig_time:%dns\n",sm2_sig_end.Sub(sm2_sig_start).Nanoseconds()/100000)

	sm2_sig_start = time.Now()
	for index=100000;index>0;index-- {
		sig2 = ed25519.Sign(&PriKey, Sig_Msg2)
	}
	sm2_sig_end = time.Now()
	fmt.Printf("Sig_time:%dns(4 times length)\n",sm2_sig_end.Sub(sm2_sig_start).Nanoseconds()/100000)

	sm2_sig_start = time.Now()
	for index=100000;index>0;index-- {
		sig3 = ed25519.Sign(&PriKey, Sig_Msg3)
	}
	sm2_sig_end = time.Now()
	fmt.Printf("Sig_time:%dns(16 times length)\n",sm2_sig_end.Sub(sm2_sig_start).Nanoseconds()/100000)

	sm2_ver_start := time.Now()
	for index=100000;index>0;index-- {
		_=ed25519.Verify(publicKey, Sig_Msg, sig)
	}
	sm2_ver_end := time.Now()
	fmt.Printf("Ver_time:%dns\n",sm2_ver_end.Sub(sm2_ver_start).Nanoseconds()/100000)

	sm2_ver_start = time.Now()
	for index=100000;index>0;index-- {
		_=ed25519.Verify(publicKey, Sig_Msg2, sig2)
	}
	sm2_ver_end = time.Now()
	fmt.Printf("Ver_time:%dns(4 times length)\n",sm2_ver_end.Sub(sm2_ver_start).Nanoseconds()/100000)

	sm2_ver_start = time.Now()
	for index=100000;index>0;index-- {
		_=ed25519.Verify(publicKey, Sig_Msg3, sig3)
	}
	sm2_ver_end = time.Now()
	fmt.Printf("Ver_time:%dns(16 times length)\n",sm2_ver_end.Sub(sm2_ver_start).Nanoseconds()/100000)

	//if(x&&y&&z){
	//	fmt.Println("true")
	//}

}
