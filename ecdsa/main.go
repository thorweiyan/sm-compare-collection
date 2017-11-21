package main

import (
	//"io"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	//"crypto/sha512"
	"fmt"
	"time"
)

const (
	PublicKeySize  = 32
	PrivateKeySize = 64
	SignatureSize  = 64
)

var (
	randKey  string
	randSign string
	prk      *ecdsa.PrivateKey
	puk      ecdsa.PublicKey
	//curve    elliptic.Curve
)

func main() {
	/*
		var PriKey = [PrivateKeySize]byte{0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 0xc5, 0xb8}
		publicKey := new([32]byte)

		h := sha512.New()
		h.Write(PriKey[:32])
		digest := h.Sum(nil)

		digest[0] &= 248
		digest[31] &= 127
		digest[31] |= 64*/

	prk, _ = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	puk = prk.PublicKey

	/*var A edwards25519.ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], digest)
	edwards25519.GeScalarMultBase(&A, &hBytes)
	A.ToBytes(publicKey)*/

	//copy(PriKey[32:], publicKey[:])
	var Sig_Msg = []byte("Sign_Test_Message")
	var Sig_Msg2 = []byte("Sign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_Message")
	var Sig_Msg3 = []byte("Sign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_Message")
	//var sig, sig2, sig3 *[ed25519.SignatureSize]byte
	var index int
	//var x bool
	r1, s1, _ := ecdsa.Sign(rand.Reader, prk, Sig_Msg)
	r2, s2, _ := ecdsa.Sign(rand.Reader, prk, Sig_Msg2)
	r3, s3, _ := ecdsa.Sign(rand.Reader, prk, Sig_Msg3)

	ecdsa_sig_start := time.Now()
	for index = 10000; index > 0; index-- {
		r1, s1, _ = ecdsa.Sign(rand.Reader, prk, Sig_Msg)
	}
	ecdsa_sig_end := time.Now()
	fmt.Printf("Sig_time:%dns\n", ecdsa_sig_end.Sub(ecdsa_sig_start).Nanoseconds()/10000)

	ecdsa_sig_start = time.Now()
	for index = 10000; index > 0; index-- {
		r2, s2, _ = ecdsa.Sign(rand.Reader, prk, Sig_Msg2)
	}
	ecdsa_sig_end = time.Now()
	fmt.Printf("Sig_time:%dns(4 times length)\n", ecdsa_sig_end.Sub(ecdsa_sig_start).Nanoseconds()/10000)

	ecdsa_sig_start = time.Now()
	for index = 10000; index > 0; index-- {
		r3, s3, _ = ecdsa.Sign(rand.Reader, prk, Sig_Msg3)
	}
	ecdsa_sig_end = time.Now()
	fmt.Printf("Sig_time:%dns(16 times length)\n", ecdsa_sig_end.Sub(ecdsa_sig_start).Nanoseconds()/10000)

	ecdsa_ver_start := time.Now()
	for index = 10000; index > 0; index-- {
		_ = ecdsa.Verify(&puk, Sig_Msg, r1, s1)
	}
	ecdsa_ver_end := time.Now()
	fmt.Printf("Ver_time:%dns\n", ecdsa_ver_end.Sub(ecdsa_ver_start).Nanoseconds()/10000)

	ecdsa_ver_start = time.Now()
	for index = 10000; index > 0; index-- {
		_ = ecdsa.Verify(&puk, Sig_Msg2, r2, s2)
	}
	ecdsa_ver_end = time.Now()
	fmt.Printf("Ver_time:%dns(4 times length)\n", ecdsa_ver_end.Sub(ecdsa_ver_start).Nanoseconds()/10000)

	ecdsa_ver_start = time.Now()
	for index = 10000; index > 0; index-- {
		_ = ecdsa.Verify(&puk, Sig_Msg3, r3, s3)
	}
	ecdsa_ver_end = time.Now()
	fmt.Printf("Ver_time:%dns(16 times length)\n", ecdsa_ver_end.Sub(ecdsa_ver_start).Nanoseconds()/10000)
}
