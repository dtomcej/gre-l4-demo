package main

import (
	"fmt"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	url := fmt.Sprintf("%v %v %v", r.Method, r.URL, r.Proto)
	fmt.Println("Got request: " + url)
	fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}

func main() {
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe("192.168.1.114:9090", nil))
}
