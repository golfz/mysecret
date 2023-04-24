package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/term"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var ivBytes = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

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
	fileName             string
	text                 string
	password             string
	method               int
	isRemoveOriginalFile bool = false
)

func main() {
	var result string
	var err error = nil
	const isEnterPasswordAgain bool = true

	text, fileName = getArgs()

	if method == method_encrypt {
		enterPassword(isEnterPasswordAgain)
	} else {
		enterPassword(!isEnterPasswordAgain)
	}

	confirmStartProcess()

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

func enterPassword(isEnterPasswordAgain bool) {
	var bytePassword1 []byte
	var err error = nil

	for {
		fmt.Print("Enter password: ")
		bytePassword1, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println()

		if !isEnterPasswordAgain {
			break

		} else if isEnterPasswordAgain {
			fmt.Print("Enter password again: ")
			bytePassword2, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println()

			if bytes.Equal(bytePassword1, bytePassword2) {
				fmt.Println("Password is matched")
				break
			} else {
				fmt.Println("Passwords do not match. Try again.")
			}
		}
	}

	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Do you want to view password? (y/n)")
		text, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading input:", err)
			return
		}
		ans := strings.ToLower(strings.TrimSpace(text))
		if ans == "y" {
			fmt.Println("Password: ", string(bytePassword1))
			break
		} else if ans == "n" {
			break
		} else {
			fmt.Println("Input was not corrected, Please enter y or n")
			continue
		}
	}

	password = string(bytePassword1)
	password = strings.TrimSpace(password)
	password = resizePasswordTo32(password)
}

func confirmStartProcess() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Do you want to start process? (y/n)")
	text, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input:", err)
		return
	}
	ans := strings.ToLower(strings.TrimSpace(text))
	if ans == "y" {
		return
	} else if ans == "n" {
		os.Exit(0)
	} else {
		fmt.Println("Input was not corrected, Please enter y or n")
		confirmStartProcess()
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
		if arg == "--remove" || arg == "-r" {
			isRemoveOriginalFile = true
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
	fmt.Println("usage: mysecret [--text|-t] [text] [--file|-f] [file] [--encrypt|-e] [--decrypt|-d] [--remove|-r] [--help|-h]")
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
	cfb := cipher.NewCFBEncrypter(block, ivBytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	encryptedText := encode(cipherText)

	if validateFileContentWithHash(plainText, []byte(encryptedText), password) {
		fmt.Println("  > Validated original & encrypted files content with hash: OK")
	} else {
		fmt.Println("Error: encrypted file content is not equal to original file content")
		os.Exit(1)
	}

	return encryptedText, nil
}

func decrypt(text, password string) (string, error) {
	block, err := aes.NewCipher([]byte(password))
	if err != nil {
		return "", err
	}
	cipherText := decode(text)
	cfb := cipher.NewCFBDecrypter(block, ivBytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}

func validateFileContentWithHash(originalFileContent []byte, encryptedFileContent []byte, password string) bool {
	originalFileHash := sha256.Sum256(originalFileContent)

	decryptFileContent, err := decrypt(string(encryptedFileContent), password)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	decryptedFileHash := sha256.Sum256([]byte(decryptFileContent))

	return bytes.Equal(originalFileHash[:], decryptedFileHash[:])
}

func getFileExtension(fileName string) string {
	return fileName[strings.LastIndex(fileName, "."):]
}

func getFileNameWithoutExtension(fileName string) string {
	return fileName[:strings.LastIndex(fileName, ".")]
}

func writeResultToFile(fileName string, text string) {
	originalFileName := fileName

	fileName = filepath.Base(fileName)

	if method == method_encrypt {
		fileName = strings.Replace(fileName, decrypt_file_suffix, "", -1)
		fileName = fileName + encrypt_file_ext
	} else {
		fileName = strings.Replace(fileName, encrypt_file_ext, "", -1)
	}

	writeFile(fileName, text)
	fmt.Println("  > Write result to file: " + fileName)

	if isRemoveOriginalFile {
		removeFile(originalFileName)
	}
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

func removeFile(fileName string) {
	err := os.Remove(fileName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("  > original file was removed: " + fileName)
}
