package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"golang.org/x/term"
	"os"
	"strings"
	"syscall"
)

var bytes = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

const (
	salt                = "gu&A0@5NEzr6iEWI1y31xNzeLMU!29pujTmRFCNQ#W^$x9yH&P"
	encrypt_file_suffix = "_encrypt"
	decrypt_file_suffix = "_decrypt"
)

const (
	method_encrypt = iota
	method_decrypt
)

var (
	fileName string
	text     string
	password string
	method   int
)

func main() {
	var result string

	text, fileName = getArgs()

	fmt.Print("Enter password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	password = string(bytePassword)
	password = strings.TrimSpace(password)
	password = resizePasswordTo32(password)

	if fileName != "" {
		text = readFile(fileName)
	}

	if method == method_encrypt {
		result, err = encrypt(text, password)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else {
		result, err = decrypt(text, password)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if fileName != "" {
		writeResultTofile(fileName, result)
	} else {
		fmt.Println(result)
	}
}

func getArgs() (text string, fileName string) {
	args := os.Args

	for i, arg := range args {
		if arg == "--encrypt" || arg == "-e" {
			method = method_encrypt
		}
		if arg == "--decrypt" || arg == "-d" {
			method = method_decrypt
		}
		if arg == "--text" || arg == "-t" {
			v := args[i+1]
			text = v
		}
		if arg == "--file" || arg == "-f" {
			v := args[i+1]
			fileName = v
		}
		if arg == "--help" || arg == "-h" {
			fmt.Println("usage: mysecret [--text|-t] [text] [--file|-f] [file] [--encrypt|-e] [--decrypt|-d] [--help|-h]")
			os.Exit(0)
		}
	}
	return
}

func resizePasswordTo32(password string) string {
	if len(password) < 32 {
		password += salt
	}
	if len(password) > 32 {
		password = password[:32]
	}
	return password
}

func readFile(fileName string) string {
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer file.Close()

	var text string
	fmt.Fscanln(file, &text)
	return text
}

func encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func encrypt(text string, password string) (string, error) {
	block, err := aes.NewCipher([]byte(password))
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, bytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return encode(cipherText), nil
}

func decrypt(text, password string) (string, error) {
	block, err := aes.NewCipher([]byte(password))
	if err != nil {
		return "", err
	}
	cipherText := decode(text)
	cfb := cipher.NewCFBDecrypter(block, bytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}

func getFileExtension(fileName string) string {
	return fileName[strings.LastIndex(fileName, "."):]
}

func getFileNameWithoutExtension(fileName string) string {
	return fileName[:strings.LastIndex(fileName, ".")]
}

func writeResultTofile(fileName string, text string) {
	if method == method_encrypt {
		fileName = getFileNameWithoutExtension(fileName) + encrypt_file_suffix + getFileExtension(fileName)
	} else {
		fileName = getFileNameWithoutExtension(fileName) + decrypt_file_suffix + getFileExtension(fileName)
	}
	writeFile(fileName, text)
}

func writeFile(fileName string, text string) {
	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer file.Close()

	file.WriteString(text)
}
