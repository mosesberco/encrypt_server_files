package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

type FileInfo struct {
	Name string "json:name"
	Hash string "json:hash"
	Size int64  "json:size"
}

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
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return
		}

		hash := hasher.Sum(nil)
		fmt.Printf("File Hash (SHA-256): %s\n", hex.EncodeToString(hash))
		file.Seek(0, io.SeekStart)
		encryptedData, err := encryptFile(file, key)
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
func encryptFile(file io.Reader, key []byte) ([]byte, error) {

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

func decryptFile(filename string, key []byte) ([]byte, error) {
	// Read the encrypted file
	encryptedData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM mode AEAD
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract the nonce from the beginning of the encrypted data
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data is too short")
	}
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
func getFileList(w http.ResponseWriter, r *http.Request) {
	directory := "api/upload"
	fmt.Print("in the func")
	files, err := ioutil.ReadDir(directory)
	if err != nil {
		return
	}
	var files_data []FileInfo
	for _, file := range files {
		if !file.IsDir() {
			fullPath := filepath.Join(directory, file.Name())

			hash, err := calculateFileHash(fullPath)
			if err != nil {
				http.Error(w, "Unable to calculate file hash", http.StatusInternalServerError)
				return
			}
			files_data = append(files_data, FileInfo{Name: file.Name(),
				Hash: hash,
				Size: file.Size()})

		}
	}
	// jsonResponse, err:= json.Marshal(files_data)
	if err != nil {
		return
	}
	tmpl, err := template.ParseFiles("list.html")
	if err != nil {
		http.Error(w, "Unable to load template", http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, files_data)
	if err != nil {
		http.Error(w, "Unable to render template", http.StatusInternalServerError)
	}
	// w.Header().Set("Content-Type", "application/json")
	// PrintFilesInfo(files_data)
	// w.Write(jsonResponse)

}
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
func PrintFilesInfo(data []FileInfo) {
	for fileinfo := range data {
		fmt.Println("%+v", fileinfo)
	}
}
func main() {
	if _, err := os.Stat("api/upload"); os.IsNotExist(err) {
		os.MkdirAll("api/upload", 0755)
	}
	// Serve the HTML file
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	// Handle file upload
	http.HandleFunc("/api/upload", uploadHandler)
	// http.HandleFunc("/api/list", getFileList)
	http.HandleFunc("/api/list", getFileList)

	// Create an uploads directory

	// Start the server
	fmt.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
