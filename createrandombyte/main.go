package main
import(
	"io/ioutil"
	//"os"
	"math/rand"
	"encoding/binary"
	"time"
	"bytes"
	"fmt"
)

func check(e error){
	if e!=nil{
		panic(e)
	}
}

func main(){
	rand.Seed(time.Now().Unix())
	d2 := bytes.NewBuffer([]byte{})
	var d3 []byte

	for index:=0;index<10000;index++{
		x := rand.Int()
		binary.Write(d2,binary.BigEndian,int32(x))
		d3 = append(d3,d2.Bytes()...)
	}

	err:= ioutil.WriteFile("data2.txt",d3,0644)
	check(err)
	fmt.Println(len(d3))
}
