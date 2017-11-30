package main

import (
	"fmt"
	"time"
	"./SM2"
	"math/big"
	"io/ioutil"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main(){
	var im *big.Int
	im = big.NewInt(1)
	fmt.Println(im)
	/******  SM2 Singature  ******/
	fmt.Println("******************************************************************")
	fmt.Println("<SM2_Singature>")
	dat,err := ioutil.ReadFile("data.txt")
	check(err)
	SM2_Sig_Msg2 := []byte(dat)
	var Err,Err2 uint32
	var SM2_Sig_PriKey = []uint8{0x12, 0x8B, 0x2F, 0xA8, 0xBD, 0x43, 0x3C, 0x6C, 0x06, 0x8C, 0x8D, 0x80, 0x3D, 0xFF, 0x79, 0x79, 0x2A, 0x51, 0x9A, 0x55, 0x17, 0x1B, 0x1B, 0x65, 0x0C, 0x23, 0x66, 0x1D, 0x15, 0x89, 0x72, 0x63}
	var IDA = []uint8{0x41, 0x4C, 0x49, 0x43, 0x45, 0x31, 0x32, 0x33, 0x40, 0x59, 0x41,0x48, 0x4F, 0x4F, 0x2E, 0x43, 0x4F,0x4D} //ASCII code of userA's identification
	var SM2_Sig_Msg string = "Sign_Test_Message"
	//var SM2_Sig_Msg2 string = "Sign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_MessageSign_Test_Message"
	fmt.Printf("\n@Signature\n")
	var R,S,PubKey,R2,S2 []uint8

	sm2_sig_start := time.Now()
	for index:=100000 ; index>0 ; index-- {
		R, S, PubKey, Err = SM2.SM2_Si(SM2_Sig_PriKey, IDA, []uint8(SM2_Sig_Msg))
	}
	sm2_sig_end := time.Now()
	fmt.Printf("Sig_time:%dns\n",sm2_sig_end.Sub(sm2_sig_start).Nanoseconds()/100000)

	sm2_sig_start = time.Now()
	for index:=100 ; index>0 ; index-- {
			R2, S2, _, Err2 = SM2.SM2_Si(SM2_Sig_PriKey, IDA, []uint8(SM2_Sig_Msg2))
	}
	sm2_sig_end = time.Now()
	fmt.Printf("Sig_time:%dns(more longer message)\n",sm2_sig_end.Sub(sm2_sig_start).Nanoseconds()/100)

	fmt.Printf("SM2_Sig_PriKey:: %x\n",SM2_Sig_PriKey)
	fmt.Printf("SM2_Sig_PubKey:: %x\n",PubKey)
	fmt.Printf("IDA:: %x\n",IDA)
	fmt.Printf("SM2_Sig_Msg(String):: %v\n",SM2_Sig_Msg)
	fmt.Printf("R::%x\n",R)
	fmt.Printf("S::%x\n",S)
	fmt.Printf("R2::%x\n",R2)
	fmt.Printf("S2::%x\n",S2)
	fmt.Printf("Err::%x\n",Err)
	fmt.Printf("Err2::%x\n",Err2)

	fmt.Printf("\n@Verify\n")
	var VerifyResult,VerifyResult2 bool

	sm2_ver_start := time.Now()
	for index:=100000 ; index>0 ; index-- {
		VerifyResult, Err = SM2.SM2_Ve(PubKey, IDA, []uint8(SM2_Sig_Msg), R, S)
	}
	sm2_ver_end := time.Now()
	fmt.Printf("Verify_time:%dns\n",sm2_ver_end.Sub(sm2_ver_start).Nanoseconds()/100000)

	sm2_ver_start = time.Now()
	for index:=100 ; index>0 ; index-- {
		VerifyResult2, Err2 = SM2.SM2_Ve(PubKey, IDA, []uint8(SM2_Sig_Msg2), R2, S2)
	}
	sm2_ver_end = time.Now()
	fmt.Printf("Verify_time:%dns(more longer message)\n",sm2_ver_end.Sub(sm2_ver_start).Nanoseconds()/100)

	fmt.Printf("VerifyResult::%v\n",VerifyResult)
	fmt.Printf("VerifyResult2::%v\n",VerifyResult2)
	fmt.Printf("Err::%x\n",Err)
	fmt.Printf("Err2::%x\n",Err2)

	fmt.Println("<SM2_Singature/>")
	fmt.Println("******************************************************************")
}
