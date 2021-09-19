package go_hibp

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HIBPUrl represents the main API url for the HIBP password API
const HIBPUrl = "https://api.pwnedpasswords.com/range/"

// Check queries the HIBP database and checks if a given string is was found
func Check(p string) (ip bool, err error) {
	shaSum := fmt.Sprintf("%x", sha1.Sum([]byte(p)))
	fp := shaSum[0:5]
	sp := shaSum[5:]
	ip = false

	httpClient := &http.Client{Timeout: time.Second * 2}
	httpRes, err := httpClient.Get(HIBPUrl + fp)
	if err != nil {
		return false, err
	}
	defer func() {
		err = httpRes.Body.Close()
	}()

	scanObj := bufio.NewScanner(httpRes.Body)
	for scanObj.Scan() {
		scanLine := strings.SplitN(scanObj.Text(), ":", 2)
		if strings.ToLower(scanLine[0]) == sp {
			ip = true
			break
		}
	}
	if err := scanObj.Err(); err != nil {
		return ip, err
	}

	return ip, nil
}
