# go-hibp - Simple go client for the HIBP API

[![Go Reference](https://pkg.go.dev/badge/github.com/wneessen/go-hibp.svg)](https://pkg.go.dev/github.com/wneessen/go-hibp) [![Go Report Card](https://goreportcard.com/badge/github.com/wneessen/go-hibp)](https://goreportcard.com/report/github.com/wneessen/go-hibp) [![Build Status](https://api.cirrus-ci.com/github/wneessen/go-hibp.svg)](https://cirrus-ci.com/github/wneessen/go-hibp)

## Usage

### Pwned Passwords API
```go
package main

import (
	"fmt"
	"github.com/wneessen/go-hibp"
)

func main() {
	hc := New()
	m, _, err := hc.PwnedPassword.CheckPassword("test123")
	if err != nil {
		panic(err)
	}
	if m != nil && m.Count != 0 {
		fmt.Println("Your password was found in the pwned passwords DB")
    }
}
```