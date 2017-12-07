package main

import (
	"crypto/aes"
	"crypto/cipher"
	//"crypto/rand"
	//"encoding/hex"
	"fmt"
	//"io"
	"time"
	//"io/ioutil"
	"io/ioutil"
)

func main(){
	var index int
	//var key = []byte{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}
	var cbc_iv = []byte{0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00}
	var gcm_iv = []byte{0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00}
	var key = []uint8{0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30}
	var CypherText,DeCypherText,MAC []uint8

	dat,_ := ioutil.ReadFile("data2.txt")
	plain := []byte(dat)
	//var plain = []byte{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}

	fmt.Printf("key:%x\n",key)

	fmt.Println()
	fmt.Println("/******************gcm加密*****************/")
	enc_time_start := time.Now()
	for index = 10 ; index>0 ; index-- {
		CypherText,MAC = ExampleNewGCM_encrypt(plain,key,gcm_iv)
	}
	enc_time_end := time.Now()
	fmt.Printf("enc_time:%dns\n",enc_time_end.Sub(enc_time_start).Nanoseconds()/10)
	//fmt.Printf("cyphertext:%x\n",CypherText)
	fmt.Printf("cyphertext'length:%d\n",len(CypherText))

	//fmt.Printf("MAC:%x\n",MAC)
	fmt.Println("/******************gcm解密*****************/")
	dec_time_start := time.Now()
	for index = 10 ; index>0 ; index-- {
		DeCypherText = ExampleNewGCM_decrypt(CypherText,key,MAC)
	}
	dec_time_end := time.Now()
	fmt.Printf("dec_time:%dns\n",dec_time_end.Sub(dec_time_start).Nanoseconds()/10)
	//fmt.Printf("origintext:%x\n",DeCypherText)

	flag:=0
	if len(plain) != len(DeCypherText){
		fmt.Println("error!")
	} else {
		for i := 0; i < len(plain); i++ {
			if plain[i] != DeCypherText[i] {
				flag = 1
				break
			}
		}
		if flag == 0 {
			fmt.Println("right")
		} else {
			fmt.Println("error!")
		}
	}

	fmt.Println("/******************cbc加密*****************/")
	enc_time_start = time.Now()
	for index = 10 ; index>0 ; index-- {
		CypherText = ExampleNewCBCEncrypter(plain,key,cbc_iv)
	}
	enc_time_end = time.Now()
	fmt.Printf("enc_time:%dns\n",enc_time_end.Sub(enc_time_start).Nanoseconds()/10)
	//fmt.Printf("cyphertext:%x\n",CypherText)
	fmt.Printf("cyphertext'length:%d\n",len(CypherText))

	fmt.Println("/******************cbc解密*****************/")
	dec_time_start = time.Now()
	for index = 10 ; index>0 ; index-- {
		DeCypherText = ExampleNewCBCDecrypter(CypherText,key,cbc_iv)
	}
	dec_time_end = time.Now()
	fmt.Printf("dec_time:%dns\n",dec_time_end.Sub(dec_time_start).Nanoseconds()/10)
	//fmt.Printf("origintext:%x\n",DeCypherText)

	flag=0
	if len(plain) != len(DeCypherText){
		fmt.Println("error!")
	} else {
		for i := 0; i < len(plain); i++ {
			if plain[i] != DeCypherText[i] {
				flag = 1
				break
			}
		}
		if flag == 0 {
			fmt.Println("right")
		} else {
			fmt.Println("error!")
		}
	}
}

func ExampleNewGCM_encrypt(plaintext []byte, key []byte,nonce []byte) ([]byte,[]byte){
	// The key argument should be the AES key, either 16 or 32 bytes
	// to select AES-128 or AES-256.
	//key := []byte("AES256Key-32Characters1234567890")
	//plaintext := []byte("exampleplaintext")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	//nonce := make([]byte, 12)
	//if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
	//	panic(err.Error())
	//}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	//fmt.Printf("%x\n", ciphertext)
	return ciphertext,nonce
}

func ExampleNewGCM_decrypt(ciphertext,key,nonce []byte) []byte{
	// The key argument should be the AES key, either 16 or 32 bytes
	// to select AES-128 or AES-256.
	//key := []byte("AES256Key-32Characters1234567890")
	//ciphertext, _ := hex.DecodeString("1019aa66cd7c024f9efd0038899dae1973ee69427f5a6579eba292ffe1b5a260")

	//nonce, _ := hex.DecodeString("37b8e8a308c354048d245f6d")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	//fmt.Printf("%s\n", plaintext)
	return plaintext
	// Output: exampleplaintext
}

func ExampleNewCBCDecrypter(ciphertext,key,iv []byte) []byte{
	//key := []byte("example key 1234")
	//ciphertext, _ := hex.DecodeString("f363f3ccdcb12bb883abf484ba77d9cd7d32b5baecb3d4b1b3e0e4beffdb3ded")
	origintext := make([]byte,0,0)
	origintext = append(origintext,ciphertext...)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(origintext, origintext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	//fmt.Printf("%s\n", ciphertext)
	return PKCS5Padding_Clear(origintext)
	// Output: exampleplaintext
}

func ExampleNewCBCEncrypter(plaintext,key,iv []byte) []byte{
	//key := []byte("example key 1234")
	//plaintext := []byte("exampleplaintext")

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	plaintext = PKCS5Padding_Make(plaintext)
	//fmt.Printf("plaintext:%x\n",plaintext)
	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, len(plaintext))
	//iv := ciphertext[:aes.BlockSize]
	//if _, err := io.ReadFull(rand.Reader, iv); err != nil {
	//	panic(err)
	//}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	//fmt.Printf("%x\n", ciphertext)
	return ciphertext
}

func PKCS5Padding_Make(OriginText []uint8) []uint8{

	var textLength = uint32( len(OriginText) )
	var appendixLength = uint8(16 - textLength%16)

	var appendix = make([]uint8, appendixLength)
	var i uint8 = 0
	for ; i < appendixLength; i++ {
		appendix[i] = appendixLength
	}

	var formatedText = make([]uint8, 0, textLength + uint32(appendixLength))

	formatedText = append(OriginText[:], appendix[:]...)
	return formatedText
}
func PKCS5Padding_Clear(PaddingText []uint8) []uint8{

	var Flag = int( PaddingText[len(PaddingText)-1] )
	return PaddingText[:len(PaddingText)-Flag]
}

