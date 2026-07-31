package server

import (
	"errors"
	"net/http"
	"sort"
)

// officialPublisher is the project's own publisher. Anything else being trusted is
// the condition the dashboard must announce — not a "dev mode", which does not exist
// (TASK-0011 Decision 2: production refusal is structural, not a switch).
const officialPublisher = "latticenet"

type pluginTrustView struct {
	// NonOfficial is true when this server trusts any publisher besides the project's
	// own, or when signature enforcement for host-risk plugins has been switched off.
	NonOfficial bool `json:"non_official"`
	// Publishers lists the NAMES of trusted non-official publishers. Never key
	// material: an operator needs to know WHICH key is trusted, never its value.
	Publishers []string `json:"publishers"`
	// AllowUnsignedHostRisk is surfaced separately because it is categorically worse
	// than an extra trusted publisher — it disables signature enforcement outright.
	AllowUnsignedHostRisk bool `json:"allow_unsigned_host_risk"`
}

// handlePluginTrust reports whether this server's trust is anything other than
// "the project's own publisher, signatures enforced".
//
// It ALWAYS emits the object, including the boring case. A dashboard that renders a
// banner only when a field is present would show nothing against an older server that
// omits it — and "no banner" would then mean both "trust is normal" and "the server
// never told me". Absence must never be able to look like safety, so the answer "no"
// is stated rather than implied by silence.
//
// Readable by any authenticated operator (withAuth "") on purpose: the banner has to
// appear for whoever is looking at the screen, not only for admins.
func (s *Server) handlePluginTrust(w http.ResponseWriter, r *http.Request, _ principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, s.pluginTrustView())
}

func (s *Server) pluginTrustView() pluginTrustView {
	view := pluginTrustView{
		Publishers:            []string{},
		AllowUnsignedHostRisk: s.pluginTrust.AllowUnsignedHostRisk,
	}
	for name := range s.pluginTrust.TrustedPublishers {
		if name != officialPublisher {
			view.Publishers = append(view.Publishers, name)
		}
	}
	sort.Strings(view.Publishers)
	view.NonOfficial = len(view.Publishers) > 0 || view.AllowUnsignedHostRisk
	return view
}
