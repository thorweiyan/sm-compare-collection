package SM2

import (
	"math/big"

)
func SM2_Sign(message []uint8,length int,ZA []uint8,rand []uint8,d []uint8,R []uint8,S []uint8) uint32 {
	if !SM2_INIT_FLAG {
		SM2_Init()
	}

	var hash [32]uint8
	var M_len int = length + int(SM3_len)/8
	var M []uint8 = nil
	//var i int
	var dA, r, s, e, k =big.NewInt(0),big.NewInt(0),big.NewInt(0),big.NewInt(0),big.NewInt(0)
	var  rk, z1, z2 =big.NewInt(0),big.NewInt(0),big.NewInt(0)
	var KG *Epoint

	//Bytes_to_Big(SM2_NUMWORD, d, dA) //cinstr(dA,d);
	dA.SetBytes(d[:])
	KG = Epoint_init()
	//step1,set M=ZA||M
	//M = (char *)malloc(sizeof(char) * (M_len + 1)) 记号
	M = make([]uint8,M_len+1)
	memcpy(M, ZA, int(SM3_len)/8)
	memcpy(M[SM3_len/8:], message, length)
	//step2,generate e=H(M)
	SM3_256(M, M_len, hash[:])
	//Bytes_to_Big(int(SM3_len)/8, hash[:], e)
	e.SetBytes(hash[:])
	//fmt.Printf("hash::%x\n",hash)
	//step3:generate k
	//Bytes_to_Big(int(SM3_len)/8, rand, k)
	k.SetBytes(rand)
	//step4:calculate kG
	//ecurve_mult(k, G, KG)
	KG.x,KG.y = curve256.ScalarBaseMult(k.Bytes())
	//step5:calculate r
	//Epoint_get(KG, KGx, KGy)

	//Add(e, KGx, r)
	r.Add(e,KG.x)
	//Divide(r, n, rem)
	r.Mod(r,n)
	//judge r=0 or n+k=n?
	//Add(r, k, rk)
	rk.Add(r,k)
	if Test_Zero(r)!=0 || Test_n(rk)!=0 {
		return ERR_GENERATE_R
	}

	//step6:generate s
	z1.Add(dA,big.NewInt(1))
	tmp:=big.NewInt(0)
	tmp.ModInverse(z1,n)
	z1 = tmp
	z2.Mul(r,dA)
	z2.Mod(z2,n)
	z2.Sub(k,z2)
	z2.Add(z2,n)
	s.Mul(z2,z1)
	s.Mod(s,n)
	if Test_Zero(s)!=0 {
		return ERR_GENERATE_S
	}
	//big_to_bytes(SM2_NUMWORD, r, R, true)
	//big_to_bytes(SM2_NUMWORD, s, S, true)
	memcpy(R,r.Bytes(),len(r.Bytes()))
	memcpy(S,s.Bytes(),len(s.Bytes()))
	//fmt.Println(R)
	//free(M);
	return 0
}

func SM2_Verify(message []uint8, len int, ZA[]uint8, Px[]uint8, Py[]uint8, R[]uint8, S[]uint8) uint32 {
	if !SM2_INIT_FLAG {
		SM2_Init()
	}

	var hash [32]uint8
	var M_len int = len + int(SM3_len)/8
	var M []uint8 = nil
	var r, s, e, t, RR *big.Int
	var PA, sG, tPA *Epoint

	PA = Epoint_init()
	sG = Epoint_init()
	tPA = Epoint_init()

	PA.x.SetBytes(Px)
	PA.y.SetBytes(Py)
	r = big.NewInt(0)
	s = big.NewInt(0)
	r.SetBytes(R)
	s.SetBytes(S)

	//if Epoint_set(PAx, PAy, 0, PA) == 0 { //initialise public key
	//	return ERR_PUBKEY_INIT
	//}
	//PA.x = PAx
	//PA.y = PAy
	//step1: test if r belong to [1,n-1]
	if Test_Range(r)!=0 {
		return ERR_OUTRANGE_R
	}
	//step2: test if s belong to [1,n-1]
	if Test_Range(s)!=0 {
		return ERR_OUTRANGE_S
	}
	//step3,generate M
	M = make([]uint8,M_len+1)
	memcpy(M, ZA, 32)
	memcpy(M[32:], message, len)
	//step4,generate e=H(M)
	SM3_256(M, M_len, hash[:])
	//Bytes_to_Big(int(SM3_len)/8, hash[:], e)
	e = big.NewInt(0)
	t = big.NewInt(0)
	e.SetBytes(hash[:])
	//fmt.Printf("hash::%x\n",hash)
	//step5:generate t
	//Add(r, s, t)
	//Divide(t, n, rem)
	t.Add(r,s)
	t.Mod(t,n)
	if Test_Zero(t)!=0 {
		return ERR_GENERATE_T
	}
	//step 6: generate(x1,y1)
	//ecurve_mult(s, G, sG)
	//ecurve_mult(t, PA, tPA)
	//ecurve_add(sG, tPA)
	//Epoint_get(tPA, x1, y1)
	sG.x,sG.y = curve256.ScalarBaseMult(s.Bytes())
	tPA.x,tPA.y = curve256.ScalarMult(PA.x,PA.y,t.Bytes())
	//fmt.Printf("PAX::%x\n",Px)
	//fmt.Printf("PAX::%x\n",Py)
	tPA.x,tPA.y = curve256.Add(sG.x,sG.y,tPA.x,tPA.y)
	//step7:generate RR
	//Add(e, x1, RR)
	//Divide(RR, n, rem)
	RR = big.NewInt(0)

	RR.Add(e,tPA.x)
	RR.Mod(RR,n)

	if RR.Cmp(r) == 0 {
		return 0
	} else {
		return ERR_DATA_MEMCMP
	}
}

func SM2_Si(user_priKey []uint8, IDA []uint8, Message []uint8) ([]uint8, []uint8, []uint8, uint32) {
	if !SM2_INIT_FLAG {
		SM2_Init()
	}


	//var SM2_rand =[]uint8("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F")
	var tmp uint32 = 0
	var PubKeyMerge = make([]uint8, SM2_NUMWORD*2)

	//generate key pair
	//var PriKey *big.Int
	var PubKey *Epoint

	PubKey = Epoint_init()
	//Bytes_to_Big(len(user_priKey), user_priKey[:], PriKey) //PriKey is the standard private key's big format
	//PriKey.SetBytes(user_priKey[:])
	tmp = SM2_KeyGeneration(user_priKey, PubKey)
	if tmp != 0 {return nil, nil, nil, tmp}

	//PubKeyMerge = PubKey.x.Bytes()
	//PubKeyMerge[SM2_NUMWORD:] = PubKey.y.Bytes()
	PubKeyMerge = append(PubKey.x.Bytes(),PubKey.y.Bytes()...)
	//fmt.Printf("%x",PubKey.x.Bytes())
	var r = make([]uint8, 32)
	var s = make([]uint8, 32)// Signature424C 49 43 45 31 32 33 40 59 41 48 4F 4F 2E 43 4F 11

	var IDA_len = len(IDA)
	var ENTLA = [2]uint8{ uint8((IDA_len*8)>>8), uint8(IDA_len*8)}      //the length of userA's identification,presentation in ASCII code
	
	var Msg_len int = len(Message)	//the length of Message
	var ZA = make([]uint8, 32)		//ZA=Hash(ENTLA|| IDA|| a|| b|| Gx || Gy || xA|| yA)
	
	N := IDA_len+2+SM2_NUMWORD*6
	var Msg = make([]uint8,N,N)	//210=IDA_len+2+SM2_NUMWORD*6
	// ENTLA || IDA || a || b || Gx || Gy || xA || yA
	memcpy(Msg[:], ENTLA[:], 2)
	memcpy(Msg[2:N], IDA[:], IDA_len)
	memcpy(Msg[2+IDA_len:N], SM2_a[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD:N], SM2_b[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*2:N], SM2_Gx[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*3:N], SM2_Gy[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*4:N], PubKeyMerge[:], SM2_NUMWORD*2)	
	SM3_256(Msg[:], N, ZA[:])

	tmp = ERR_GENERATE_R

	for ;tmp==ERR_GENERATE_R || tmp==ERR_GENERATE_S;{
		SM2_rand := Rand_Gen( SM2_n[:] )
		tmp = SM2_Sign(Message, Msg_len, ZA[:], SM2_rand, user_priKey[:], r[:], s[:])
	}
	SM2_INIT_FLAG = false
	return r, s, PubKeyMerge, 0
}

func SM2_Ve(user_pubKey []uint8, IDA []uint8, Message []uint8, R []uint8, S []uint8) (bool, uint32) {
	if !SM2_INIT_FLAG {
		SM2_Init()
	}

	var tmp uint32 = 0

	var IDA_len = len(IDA)
	var ENTLA = [2]uint8{ uint8((IDA_len*8)>>8), uint8(IDA_len*8)}      //the length of userA's identification,presentation in ASCII code
	
	var Msg_len int = len(Message)	//the length of Message
	var ZA [32]uint8		//ZA=Hash(ENTLA|| IDA|| a|| b|| Gx || Gy || xA|| yA)
	
	N := IDA_len+2+SM2_NUMWORD*6
	Msg := make([]uint8,N,N)	//210=IDA_len+2+SM2_NUMWORD*6
	// ENTLA || IDA || a || b || Gx || Gy || xA || yA
	memcpy(Msg[:], ENTLA[:], 2)
	memcpy(Msg[2:N], IDA[:], IDA_len)
	memcpy(Msg[2+IDA_len:N], SM2_a[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD:N], SM2_b[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*2:N], SM2_Gx[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*3:N], SM2_Gy[:], SM2_NUMWORD)
	memcpy(Msg[2+IDA_len+SM2_NUMWORD*4:N], user_pubKey[:], SM2_NUMWORD*2)	
	SM3_256(Msg[:], N, ZA[:])

	tmp = SM2_Verify(Message, Msg_len, ZA[:], user_pubKey[:SM2_NUMWORD], user_pubKey[SM2_NUMWORD:], R, S)
	if tmp != 0 {return false, tmp}
	SM2_INIT_FLAG = false
	return true, 0
}
