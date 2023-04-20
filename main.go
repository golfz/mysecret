package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"golang.org/x/term"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var bytes = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

const (
	salt                = "gu&A0@5NEzr6iEWI1y31xNzeLMU!29pujTmRFCNQ#W^$x9yH&P"
	encrypt_file_ext    = ".encrypted"
	decrypt_file_suffix = ".decrypted"
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
		writeResultToFile(fileName, result)
	} else {
		fmt.Println(result)
	}
}

func getArgs() (text string, fileName string) {
	args := os.Args

	isFoundArgs := false

	for i, arg := range args {
		if arg == "--encrypt" || arg == "-e" {
			method = method_encrypt
			isFoundArgs = true
		}
		if arg == "--decrypt" || arg == "-d" {
			method = method_decrypt
			isFoundArgs = true
		}
		if arg == "--text" || arg == "-t" {
			v := args[i+1]
			text = v
			isFoundArgs = true
		}
		if arg == "--file" || arg == "-f" {
			v := args[i+1]
			fileName = v
			isFoundArgs = true
		}
		if arg == "--help" || arg == "-h" {
			printHelp()
			isFoundArgs = true
		}
	}

	if !isFoundArgs {
		printHelp()
	}

	return
}

func printHelp() {
	fmt.Println("usage: mysecret [--text|-t] [text] [--file|-f] [file] [--encrypt|-e] [--decrypt|-d] [--help|-h]")
	os.Exit(0)
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

//func readFile(fileName string) string {
//	file, err := os.Open(fileName)
//	if err != nil {
//		fmt.Println(err)
//		os.Exit(1)
//	}
//	defer file.Close()
//
//	var text string
//	fmt.Fscanln(file, &text)
//	return text
//}

func readFile(fileName string) string {
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var text string
	for scanner.Scan() {
		text += scanner.Text() + "\n"
	}
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

func writeResultToFile(fileName string, text string) {
	fileName = filepath.Base(fileName)

	if method == method_encrypt {
		fileName = strings.Replace(fileName, decrypt_file_suffix, "", -1)
		fileName = fileName + encrypt_file_ext
	} else {
		fileName = strings.Replace(fileName, encrypt_file_ext, "", -1)
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
