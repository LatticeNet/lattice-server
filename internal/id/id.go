package id

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
	"time"
)

func New(prefix string) string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return prefix + "_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	}
	token := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
	return prefix + "_" + token
}
