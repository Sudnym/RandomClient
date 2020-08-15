package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"github.com/smallnest/goframe"
	"github.com/therecipe/qt/widgets"
	"net"
	"os"
)

var conn net.Conn
var err error

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
	defer conn.Close()
	// needs to be called once before you can start using the QWidgets
	app := widgets.NewQApplication(len(os.Args), os.Args)

	// create a window
	// with a minimum size of 250*200
	// and sets the title to "Hello Widgets Example"
	window := widgets.NewQMainWindow(nil, 0)
	window.SetMinimumSize2(250, 200)
	window.SetWindowTitle("RandomClient")

	// create a regular widget
	// give it a QVBoxLayout
	// and make it the central widget of the window
	widget := widgets.NewQWidget(nil, 0)
	widget.SetLayout(widgets.NewQVBoxLayout())
	window.SetCentralWidget(widget)

	// create a line edit
	// with a custom placeholder text
	// and add it to the central widgets layout
	input := widgets.NewQLineEdit(nil)
	input.SetPlaceholderText("Enter IP...")
	widget.Layout().AddWidget(input)

	// create a button
	// connect the clicked signal
	// and add it to the central widgets layout
	button := widgets.NewQPushButton2("Connect", nil)
	button.ConnectClicked(func(bool) {
		ip := input.Text()
		ip += ":9000"
		conn, err = net.Dial("tcp", ip)
		input.SetPlaceholderText("Send a message...")
		button.SetText("Send")
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
		if err != nil {
			panic(err)
		}
		var key rsa.PublicKey
		err = json.Unmarshal(data, &key)
		button.ConnectClicked(func(bool) {
			message := input.Text()
			data = []byte(encrypt(message, key))
			err = fc.WriteFrame(data)
			if err != nil {
				panic(err)
			}
		})
	})
	widget.Layout().AddWidget(button)

	// make the window visible
	window.Show()

	// start the main Qt event loop
	// and block until app.Exit() is called
	// or the window is closed by the user
	app.Exec()
}
