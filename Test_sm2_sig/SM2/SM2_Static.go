package SM2
import(
	"math/big"
	"crypto/elliptic"
	//"bytes"
	//"encoding/binary"
)

type Epoint struct {
	x *big.Int
	y *big.Int
}
var ECC_WORDSIZE uint32 = 8
var SM2_WORDSIZE int = 8
var SM2_NUMBITS int = 256
var SM2_NUMWORD int = 32
var ERR_INFINITY_POINT uint32 = 0x00000001
var ERR_NOT_VALID_ELEMENT uint32 = 0x00000002
var ERR_NOT_VALID_POINT uint32 = 0x00000003
var ERR_ORDER uint32 = 0x00000004
var ERR_ARRAY_NULL uint32 = 0x00000005
var ERR_C3_MATCH uint32 = 0x00000006
var ERR_ECURVE_INIT uint32 = 0x00000007
var ERR_SELFTEST_KG uint32 = 0x00000008
var ERR_SELFTEST_ENC uint32 = 0x00000009
var ERR_SELFTEST_DEC uint32 = 0x0000000A
var ERR_PUBKEY_INIT uint32 = 0x0000000B
var ERR_DATA_MEMCMP uint32 = 0x0000000C
var ERR_GENERATE_R uint32 = 0x0000000D
var ERR_GENERATE_S uint32 = 0x0000000E
var ERR_OUTRANGE_R uint32 = 0x0000000F
var ERR_OUTRANGE_S uint32 = 0x00000010
var ERR_GENERATE_T uint32 = 0x00000011

/* 椭圆曲线方程为： y2 = x3 + ax + b     >>>   elliptic-256 a=-3 */
var SM2_p []uint8
var SM2_a =[]uint8{0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfd}
var SM2_b []uint8
var SM2_n []uint8
var SM2_Gx []uint8
var SM2_Gy []uint8
//var SM2_h []uint8
//var para_p, para_a, para_b, para_n, para_Gx, para_Gy, para_h =big.NewInt(0),big.NewInt(0),big.NewInt(0),big.NewInt(0),big.NewInt(0),big.NewInt(0),big.NewInt(0)
//var Gx, Gy, p, a, b, n *big.Int//=big.NewInt(0),big.NewInt(0),big.NewInt(0),big.NewInt(0),big.NewInt(0),big.NewInt(0)
var n=big.NewInt(0)
var G, nG *Epoint
var curve256 elliptic.Curve
var SM2_INIT_FLAG bool = false

// x3
func SM2_Init() uint32 {
	curve256 = elliptic.P256()
	SM2_p = curve256.Params().P.Bytes()
	SM2_b = curve256.Params().B.Bytes()
	SM2_n = curve256.Params().N.Bytes()
	SM2_Gx = curve256.Params().Gx.Bytes()
	SM2_Gy = curve256.Params().Gy.Bytes()
	n.SetBytes(SM2_n[:])
	SM2_INIT_FLAG = true
	return 0
}

// x3
func SM2_KeyGeneration(priKey []uint8, pubKey *Epoint) uint32 {
	if !SM2_INIT_FLAG {
		SM2_Init()
	}
	//pubKey = Epoint_init()
	x,y :=curve256.ScalarBaseMult(priKey)
	pubKey.x = x
	pubKey.y = y

	//var x, y *big.Int
	//Ecurve_mult(priKey, G, pubKey) //通过大数和基点产生公钥
	//Epoint_get(pubKey, x, y)
	if !curve256.IsOnCurve(x,y){
		return ERR_PUBKEY_INIT
	} else {
		return 0
	}

}

// for SM2_EnDe
func Test_Null(array []uint8,len int) int {
	var i int = 0
	for i = 0; i < len; i++ {
		if array[i] != 0x00 {
			return 0
		}
	}
	return 1
}

// for SM2_Signature
func Test_Zero(x *big.Int) int {
	if !SM2_INIT_FLAG {
		SM2_Init()
	}

	var zero = big.NewInt(0)
	if x.Cmp(zero) == 0 {
		return 1
	} else {
		return 0
	}
}

func Test_n(x *big.Int)int {
	if !SM2_INIT_FLAG {
		SM2_Init()
	}

	// Bytes_to_big(32,SM2_n,n);
	if x.Cmp(n) == 0 {
		return 1
	} else {
		return 0
	}
}

func Test_Range(x *big.Int)int {
	if !SM2_INIT_FLAG {
		SM2_Init()
	}

	var one, decr_n *big.Int
	one = big.NewInt(1)
	//decr(n, 1, decr_n)
	decr_n = big.NewInt(1)
	decr_n.Sub(n,one)
	if (x.Cmp(one) < 0) || (x.Cmp(decr_n) > 0) { //这里原本是(compare(x, one) < 0) | (compare(x, decr_n) > 0)
		return 1
	}
	return 0
}

func memcpy ( buf1 []uint8, buf2 []uint8,count int) {

	if count == 0{
		return
	}
	var i int =0
	for i < count  {
		buf1[i]=buf2[i]
		i++
	}
}

func Epoint_init() *Epoint { /* initialise epoint to general point at infinity. */
	var p= &Epoint{big.NewInt(0),big.NewInt(0)}
	return p
}