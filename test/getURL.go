package main

import (
	"os"
	"fmt"
	"time"
	"net/http"
)

func getURL(url string) {
	res, err := http.Get(url)
	if err != nil {
		fmt.Printf("e")
		return
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		fmt.Printf(".")
	} else {
		fmt.Printf("x")
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("%s url...\n", os.Args[0])
		return
	}

	for {
		for i, url := range os.Args[1:] {
			fmt.Printf("%d", i+1)
			getURL(url)
			time.Sleep(time.Second)
		}
	}
}
