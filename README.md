# go-hibp - Simple Go binding to the "Have I Been Pwned" API

[![GoDoc](https://godoc.org/github.com/wneessen/go-hibp?status.svg)](https://pkg.go.dev/github.com/wneessen/go-hibp) 
[![Go Report Card](https://goreportcard.com/badge/github.com/wneessen/go-hibp)](https://goreportcard.com/report/github.com/wneessen/go-hibp) 
[![Build Status](https://api.cirrus-ci.com/github/wneessen/go-hibp.svg)](https://cirrus-ci.com/github/wneessen/go-hibp)
[![codecov](https://codecov.io/gh/wneessen/go-hibp/branch/main/graph/badge.svg?token=ST96EC0JHU)](https://codecov.io/gh/wneessen/go-hibp)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge-flat.svg)](https://github.com/avelino/awesome-go) 
<a href="https://ko-fi.com/D1D24V9IX"><img src="https://uploads-ssl.webflow.com/5c14e387dab576fe667689cf/5cbed8a4ae2b88347c06c923_BuyMeACoffee_blue.png" height="20" alt="buy ma a coffee"></a>

This Go library provides simple bindings to the excellent 
"[Have I Been Pwned](https://haveibeenpwned.com/API/v3)" (HIBP) API by Troy Hunt. It implements all 3 APIs
that are provided by HIBP (Breaches, Pastes, Passwords). API key support for the private API endpoints are 
supported as well. go-hibp follows idiomatic Go style and best practice. It's only dependency is the Go Standard 
Library. 

## Usage
The library is fully documented using the execellent GoDoc functionality. Check out the
[GoDocs Reference](https://pkg.go.dev/github.com/wneessen/go-hibp) for details on how to implement 
access to any of the 3 APIs with this package. You will also find GoDoc code examples there for each of those
APIs.
