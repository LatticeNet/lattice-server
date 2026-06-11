package ddns

import (
	"net/http"
	"time"
)

func defaultClient() *http.Client { return &http.Client{Timeout: 15 * time.Second} }
