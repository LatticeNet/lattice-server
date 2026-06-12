package ddns

import (
	"net/http"
	"time"

	"github.com/LatticeNet/lattice-server/internal/outbound"
)

func defaultClient() *http.Client { return outbound.NewClient(15 * time.Second) }
