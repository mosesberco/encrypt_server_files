package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Parse the multipart form, with a maximum memory of 10MB
		r.ParseMultipartForm(10 << 20) // 10MB

		// Retrieve the file from form data
		file, handler, err := r.FormFile("uploadedFile")
		if err != nil {
			fmt.Println("Error Retrieving the File")
			fmt.Println(err)
			return
		}
		defer file.Close()

		// Create a temporary file within our server's directory
		tempFile, err := os.Create("./api/upload/" + handler.Filename)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer tempFile.Close()
		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			fmt.Println("Error hashing the file")
			fmt.Println(err)
			return
		}

		hash := hasher.Sum(nil)
		fmt.Printf("File Hash (SHA-256): %s\n", hex.EncodeToString(hash))
		file.Seek(0, io.SeekStart)
		encryptedData, err := encryptFile(file)
		if err != nil {
			fmt.Println("Error encrypting the file")
			fmt.Println(err)
			return
		}
		encryptedFileName := "./api/upload/encrypted_" + handler.Filename
		if err := os.WriteFile(encryptedFileName, encryptedData, 0644); err != nil {
			fmt.Println("Error saving the encrypted file")
			fmt.Println(err)
			return
		}

		// Return a success message
		fmt.Fprintf(w, "Successfully Uploaded File\n")
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}
func encryptFile(file io.Reader) ([]byte, error) {
	// Generate a random 32-byte key for AES-256
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM mode AEAD (Authenticated Encryption with Associated Data)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce (number used once) for GCM
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Read the file's content into a buffer
	fileData, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	// Encrypt the file data using AES-GCM
	encryptedData := gcm.Seal(nonce, nonce, fileData, nil)

	// Return the encrypted data
	return encryptedData, nil
}

func main() {
	// Serve the HTML file
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	// Handle file upload
	http.HandleFunc("/api/upload", uploadHandler)

	// Create an uploads directory
	if _, err := os.Stat("api/upload"); os.IsNotExist(err) {
		os.MkdirAll("api/upload", 0755)
	}

	// Start the server
	fmt.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
