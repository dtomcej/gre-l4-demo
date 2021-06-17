package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide host:port.")
		return
	}

	fmt.Println("Running GET Request")

	req, err := http.NewRequest(http.MethodGet, "http://"+arguments[1], nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	body, ioErr := io.ReadAll(res.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
		return
	}

	fmt.Println("Got HTTP Response: " + string(body))
}
