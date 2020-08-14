package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/smallnest/goframe"

	"github.com/monnand/dhkx"
)

var delimiter = regexp.MustCompile(`:`)

// DHEX AES encrypt / decrypt functions
func encrypt(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		fmt.Print(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter ip address: ")
	ip, _ := reader.ReadString('\n')
	ip = strings.TrimSuffix(ip, "\n")
	address := ip + ":9000"
	conn, err := net.Dial("tcp", address)
	if err != nil {
		panic(err)
	}
	fmt.Println("Connected")
	defer conn.Close()

	encoderConfig := goframe.EncoderConfig{
		ByteOrder:                       binary.BigEndian,
		LengthFieldLength:               4,
		LengthAdjustment:                0,
		LengthIncludesLengthFieldLength: false,
	}

	decoderConfig := goframe.DecoderConfig{
		ByteOrder:           binary.BigEndian,
		LengthFieldOffset:   0,
		LengthFieldLength:   4,
		LengthAdjustment:    0,
		InitialBytesToStrip: 4,
	}

	fc := goframe.NewLengthFieldBasedFrameConn(encoderConfig, decoderConfig, conn)
	g, _ := dhkx.GetGroup(0)
	priv, _ := g.GeneratePrivateKey(nil)
	pub := priv.Bytes()
	keysend := []byte{0x000C}
	for i := range pub{
		keysend = append(keysend, pub[i])
	}
	fmt.Println("Authenticating...")
	err = fc.WriteFrame(keysend)
	if err != nil {
		panic(err)
	}
	fmt.Println("Key sent...")
	data, err := fc.ReadFrame()
	if err != nil {
		panic(err)
	}
	k, _ := g.ComputeKey(dhkx.NewPublicKey(data), priv)
	fmt.Print("Enter Message: ")
	message, _ := reader.ReadString('\n')
	message = strings.TrimSuffix(message, "\n")
	data = []byte(message)
	finaldata := encrypt(data, k.Bytes())
	err = fc.WriteFrame(finaldata)
	if err != nil {
		panic(err)
	}
	fmt.Println("Message Sent")

}