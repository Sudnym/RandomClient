package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/smallnest/goframe"
)

var delimiter = regexp.MustCompile(`:`)

// DHEX AES encrypt / decrypt functions
func encrypt(secretMessage string, key rsa.PublicKey) string {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &key, []byte(secretMessage), label)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter ip address: ")
	ip, _ := reader.ReadString('\n')
	ip = strings.TrimSuffix(ip, "\n")
	ip = strings.TrimSuffix(ip, "\r")
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
	data, err := fc.ReadFrame()
	var key rsa.PublicKey
	err = json.Unmarshal(data, &key)
	fmt.Println("Key Recieved")
	for {
		fmt.Print("Enter Message: ")
		message, _ := reader.ReadString('\n')
		message = strings.TrimSuffix(message, "\n")
		message = strings.TrimSuffix(message, "\r")
		data = []byte(encrypt(message, key))
		err = fc.WriteFrame(data)
		if err != nil {
			panic(err)
		}
		fmt.Println("Message Sent")
	}

}
