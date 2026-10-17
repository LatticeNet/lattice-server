package server

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Design 31, S2 and S3: the download walks its sources, leaves a slow one
// early, gives the rest of the budget to the source that delivered the most,
// and fetches the gzip form from the control plane when the plan pins it.
//
// The walk is keyed on a plan line, as the keepalive and update guard steps
// are: a plan made now carries agentUpdateCutoffPlanLine, and the script
// renders the walk only for an approval whose plan carries it. The payload is
// unchanged by the walk, so deploying it retires no open approval; an approval
// planned before it renders the download it was approved with. Compression
// does change the payload (compressed_sha256, compressed_size, binary_size),
// and a payload that carries them only renders with the walk.
//
// Why 32 KiB/s for 30 s (design 31, D1): from byte zero the 14,037,154 byte
// binary needs 29,244 B/s to finish inside the 480 s budget, so a source under
// 32 KiB/s cannot finish alone in one attempt. The slow residential paths seen
// on 2026-10-17 ran at 23 to 25 KB/s, the mainland path at over 228 KiB/s. A
// false cut costs one reconnect and keeps every byte received, and 30 s is
// curl's own default window, long enough that a cross-border stall of a few
// seconds does not cut a good path.
const (
	agentFetchCutRate    = "32768"
	agentFetchCutWindow  = "30"
	agentFetchRetries    = "3"
	agentFetchRetryPause = "2"

	agentUpdateCutoffPlanLine = "- slow sources are left early: with more than one source, each gets at most an equal share of what is left of the " +
		agentFetchBudgetSec + " s download budget and is left once it delivers under 32 KiB/s for " + agentFetchCutWindow +
		" s, keeping what it delivered; with " + agentFetchConnectSec + " s or more left, the rest goes, without the cutoff, to the source that delivered the largest part of its file, retried up to " +
		agentFetchRetries + " times after a transient failure; with wget each source is fetched once, inside what is left of the budget when timeout is available; the task output ends with a lattice-agent-fetch line recording what each source delivered, in bytes and seconds"

	// agentFetchSummaryPrefix starts the one stderr line the walk prints on
	// every exit path. Fields follow, one per fetch, as
	// index:kind:exit:bytes:seconds, where index is the source's place in the
	// first pass or p2 for a second-pass fetch, kind is cp, cp.gz or up,
	// bytes is what that fetch added to its file, and seconds is - when the
	// node has no usable clock. The last field is result:<exit>:<stage>.
	agentFetchSummaryPrefix = "lattice-agent-fetch v1"
)

// agentUpdateWalks reports whether an approval renders the source walk: a
// resumable plan whose text carries the cutoff line.
func agentUpdateWalks(plan string, payload agentUpdatePayload) bool {
	return payload.ResumeDownload && strings.Contains(plan, agentUpdateCutoffPlanLine)
}

// agentFetchSource is one download source as the walk renders it.
type agentFetchSource struct {
	index int
	// kind names the source in the summary line.
	kind string
	// url and file are shell expressions: the URL fetched and the partial
	// file it continues. Sources that serve the same bytes share a file.
	url, file string
	// size is a shell expression for that file's full size, used only to
	// compare progress across files of different sizes. Sources of one file
	// all use "1", which makes the comparison one of bytes delivered.
	size string
	// leased marks the control-plane fetch, the only one that presents the
	// task lease and the only one that never follows a redirect.
	leased bool
	// gzip marks the compressed control-plane fetch, which a node without a
	// working gzip and head -c skips.
	gzip bool
}

func agentUpdateFetchSources(payload agentUpdatePayload) []agentFetchSource {
	compressed := payload.CompressedSHA256 != ""
	var out []agentFetchSource
	if normalizeAgentBinarySource(payload.BinarySource) == agentBinarySourceControlPlane {
		cp := agentFetchSource{kind: "cp", url: "\"$URL\"", file: "\"$CANDIDATE\"", size: "1", leased: true}
		if compressed {
			cp.kind, cp.file, cp.size, cp.gzip = "cp.gz", "\"$PACKED\"", "EXPECT_PACKED_SIZE", true
		}
		out = append(out, cp)
		if payload.FallbackURL != "" {
			up := agentFetchSource{kind: "up", url: "\"$FALLBACK_URL\"", file: "\"$CANDIDATE\"", size: "1"}
			if compressed {
				up.size = "EXPECT_SIZE"
			}
			out = append(out, up)
		}
	} else {
		out = append(out, agentFetchSource{kind: "up", url: "\"$URL\"", file: "\"$CANDIDATE\"", size: "1"})
	}
	for i := range out {
		out[i].index = i + 1
	}
	return out
}

// agentUpdateCompressedHeader declares the compressed digest and both sizes
// for a plan that pins them, and nothing otherwise.
func agentUpdateCompressedHeader(payload agentUpdatePayload) string {
	if payload.CompressedSHA256 == "" {
		return ""
	}
	return "EXPECT_PACKED_SHA=" + shellQuote(payload.CompressedSHA256) + "\n" +
		"EXPECT_PACKED_SIZE=" + shellQuote(strconv.Itoa(payload.CompressedSize)) + "\n" +
		"EXPECT_SIZE=" + shellQuote(strconv.Itoa(payload.BinarySize)) + "\n"
}

// agentUpdateSummaryStep arms the summary line. It runs before the systemd
// checks, so a node without systemd or without the service still reports a
// line, with no fetches and the stage it stopped in.
func agentUpdateSummaryStep(walk bool) string {
	if !walk {
		return ""
	}
	return "FETCH_LOG=\"\"\n" +
		"FETCH_STAGE=prepare\n" +
		"fetch_summary() {\n" +
		"  echo \"" + agentFetchSummaryPrefix + "$FETCH_LOG result:$1:$FETCH_STAGE\" >&2\n" +
		"}\n" +
		"trap 'fetch_summary \"$?\"' EXIT\n"
}

// agentUpdateStageLine moves the summary line's stage along for a script
// that walks, and is empty for one that does not.
func agentUpdateStageLine(walk bool, stage string) string {
	if !walk {
		return ""
	}
	return "FETCH_STAGE=" + stage + "\n"
}

// agentUpdateWalkCandidateStep is agentUpdateCandidateStep for the walk. The
// binary's kept download is named by its digest as before; a compressed plan
// keeps the compressed download beside it, named by the compressed digest.
// Kept files for any other digest are removed, and a kept file is continued
// only when it is a regular file, not a symlink, owned by the user the script
// runs as.
func agentUpdateWalkCandidateStep(compressed bool) string {
	keep := "\"$CANDIDATE\""
	b := strings.Builder{}
	b.WriteString("PARTIAL_DIR=$(dirname \"$TARGET\")\n" +
		"mkdir -p \"$PARTIAL_DIR\"\n" +
		"CANDIDATE=\"$PARTIAL_DIR/" + agentUpdatePartialPrefix + "$EXPECT_SHA\"\n")
	if compressed {
		b.WriteString("PACKED=\"$PARTIAL_DIR/" + agentUpdatePartialPrefix + "$EXPECT_PACKED_SHA\"\n")
		keep = "\"$CANDIDATE\"|\"$PACKED\""
	}
	b.WriteString("for KEPT in \"$PARTIAL_DIR\"/" + agentUpdatePartialPrefix + "*; do\n" +
		"  case \"$KEPT\" in\n" +
		"    " + keep + ") ;;\n" +
		"    *) rm -rf \"$KEPT\" ;;\n" +
		"  esac\n" +
		"done\n")
	b.WriteString("for KEPT in " + strings.ReplaceAll(keep, "|", " ") + "; do\n" +
		"  if [ -f \"$KEPT\" ] && [ ! -L \"$KEPT\" ] && [ -O \"$KEPT\" ]; then\n" +
		"    chmod 0600 \"$KEPT\"\n" +
		"    echo \"lattice agent update: continuing the download an earlier attempt kept in $KEPT ($(wc -c <\"$KEPT\") bytes)\"\n" +
		"  else\n" +
		"    rm -rf \"$KEPT\"\n" +
		"  fi\n" +
		"done\n")
	return b.String()
}

// agentUpdateWalkStep renders the download for a plan that walks its sources.
//
// First pass: each source the node can use, in plan order, gets at most an
// equal share of what is left of the budget (what is left divided by the
// sources not yet tried) and, with curl and more than one source, is left as
// soon as it delivers under the cutoff rate for the cutoff window. Every
// source is cut, the last one included: an uncut last source, which for an
// official release is GitHub, could hold the whole budget while the best
// source sat idle. The first fetch that completes ends the walk.
//
// Second pass, curl only: with at least one connect timeout of the budget
// left, the source that delivered the largest part of its file in this
// attempt gets everything that remains, without the cutoff, retried after a
// transient failure up to the retry count with a short pause. A source that
// delivered nothing is never chosen. With a single source the first pass has
// no cutoff, since there is nothing to switch to, and the second pass is its
// retry.
//
// wget has no speed cutoff. It fetches each source once, wrapped in timeout
// with what is left of the budget when a timeout that takes a plain number of
// seconds exists, and makes no second pass.
//
// Exit 33 means a source ignored the range. The walk moves on and keeps the
// partial, because another source can continue it; a partial is deleted only
// when every source of that file the attempt reached answered 33, which is
// S1's single-source rule generalized. Any other failure moves on too.
//
// The clock only sizes shares. A fetch on a node whose date gives no epoch
// seconds is charged its whole limit, so the walk can never run past the
// budget; a fetch whose measured time exceeds its limit (a clock that jumped)
// is charged its limit.
//
// The lease is presented on the control-plane line alone, which never
// follows a redirect; every other line follows redirects to HTTPS only and
// carries no credential. A wget that cannot do either (busybox) is refused
// with the reason named.
//
// A kept file that already holds the pinned bytes ends the walk before any
// fetch, and an incomplete walk checks its files once more before it fails
// (agentWalkKeptCheck).
func agentUpdateWalkStep(payload agentUpdatePayload) string {
	sources := agentUpdateFetchSources(payload)
	var b strings.Builder
	b.WriteString("FETCH_BUDGET=" + agentFetchBudgetSec + "\n" +
		"FETCH_CONNECT=" + agentFetchConnectSec + "\n" +
		"FETCH_CUT_RATE=" + agentFetchCutRate + "\n" +
		"FETCH_CUT_WINDOW=" + agentFetchCutWindow + "\n" +
		"FETCH_RETRIES=" + agentFetchRetries + "\n" +
		"FETCH_PAUSE=" + agentFetchRetryPause + "\n" +
		"FETCH_STAGE=fetch\n" +
		"fetch_size() {\n" +
		"  if [ -f \"$1\" ]; then echo $(($(wc -c <\"$1\"))); else echo 0; fi\n" +
		"}\n" +
		"fetch_clock() {\n" +
		"  FETCH_T=$(date +%s 2>/dev/null || true)\n" +
		"  case \"$FETCH_T\" in ''|*[!0-9]*) FETCH_T=\"\" ;; esac\n" +
		"}\n" +
		"fetch_bounded() {\n" +
		"  if [ \"$FETCH_TIMEOUT\" = 1 ]; then timeout \"$FETCH_LIMIT\" \"$@\"; else \"$@\"; fi\n" +
		"}\n")

	// One curl line and one wget line per source, so a reader of the approved
	// script sees which line carries the lease.
	b.WriteString("fetch_source() {\n  case \"$1\" in\n")
	for _, src := range sources {
		fmt.Fprintf(&b, "    %d)\n", src.index)
		b.WriteString("      if [ \"$FETCHER\" = curl ]; then\n")
		b.WriteString("        " + agentWalkCurlLine(src) + "\n")
		b.WriteString("      else\n")
		b.WriteString("        " + agentWalkWgetLine(src) + "\n")
		b.WriteString("      fi\n      ;;\n")
	}
	b.WriteString("  esac\n}\n")

	b.WriteString("fetch_one() {\n" +
		"  FETCH_BEFORE=$(fetch_size \"$3\")\n" +
		"  fetch_clock\n" +
		"  FETCH_T0=$FETCH_T\n" +
		"  FETCH_RC=0\n" +
		"  fetch_source \"$1\" || FETCH_RC=$?\n" +
		"  fetch_clock\n" +
		"  FETCH_GOT=$(($(fetch_size \"$3\") - FETCH_BEFORE))\n" +
		"  if [ \"$FETCH_GOT\" -lt 0 ]; then FETCH_GOT=0; fi\n" +
		"  FETCH_TOOK=-\n" +
		"  if [ -n \"$FETCH_T0\" ] && [ -n \"$FETCH_T\" ] && [ \"$FETCH_T\" -ge \"$FETCH_T0\" ]; then FETCH_TOOK=$((FETCH_T - FETCH_T0)); fi\n" +
		"  if [ \"$FETCH_TOOK\" = - ]; then\n" +
		"    if [ \"$FETCHER\" = wget ] && [ \"$FETCH_TIMEOUT\" = 0 ]; then FETCH_CHARGE=0; else FETCH_CHARGE=$FETCH_LIMIT; fi\n" +
		"  elif [ \"$FETCH_TOOK\" -gt \"$FETCH_LIMIT\" ]; then\n" +
		"    FETCH_CHARGE=$FETCH_LIMIT\n" +
		"  else\n" +
		"    FETCH_CHARGE=$FETCH_TOOK\n" +
		"  fi\n" +
		"  FETCH_SPENT=$((FETCH_SPENT + FETCH_CHARGE))\n" +
		"  FETCH_LOG=\"$FETCH_LOG $4:$2:$FETCH_RC:$FETCH_GOT:$FETCH_TOOK\"\n" +
		"  if [ \"$FETCH_RC\" = 0 ]; then FETCH_DONE=$1; FETCH_DONE_FILE=$3; fi\n" +
		"}\n")

	b.WriteString("if command -v curl >/dev/null 2>&1; then\n" +
		"  FETCHER=curl\n" +
		"elif command -v wget >/dev/null 2>&1; then\n" +
		"  FETCHER=wget\n" +
		"else\n" +
		"  echo 'lattice agent update: curl or wget is required' >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		// busybox wget has no --https-only and no --max-redirect, so it can
		// neither refuse plain HTTP nor keep the lease from following a
		// redirect. It rejects the options; this says why instead.
		"if [ \"$FETCHER\" = wget ] && ! wget --help 2>&1 | grep -q -- '--https-only'; then\n" +
		"  echo 'lattice agent update: this wget cannot refuse plain HTTP or redirects (busybox wget does not); the update needs curl or GNU wget' >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		// busybox before 1.30 spells it timeout -t SECS, which would run the
		// number as the command, so only a timeout that runs "true" counts.
		"FETCH_TIMEOUT=0\n" +
		"if [ \"$FETCHER\" = wget ] && command -v timeout >/dev/null 2>&1 && timeout 5 true >/dev/null 2>&1; then FETCH_TIMEOUT=1; fi\n")
	untried := make([]string, 0, len(sources))
	for _, src := range sources {
		fmt.Fprintf(&b, "FETCH_USE_%d=1\n", src.index)
		if src.gzip {
			// The compressed form needs gzip -dc and head -c, which every
			// coreutils and busybox userland has. A node where either does
			// not work skips the compressed source and walks the rest.
			fmt.Fprintf(&b, "if ! command -v gzip >/dev/null 2>&1 || [ \"$(printf x | gzip -c 2>/dev/null | gzip -dc 2>/dev/null)\" != x ] || [ \"$(printf abc | head -c 2 2>/dev/null)\" != ab ]; then\n"+
				"  FETCH_USE_%d=0\n"+
				"  echo 'lattice agent update: gzip or head -c does not work on this node, so it skips the compressed control-plane download' >&2\n"+
				"fi\n", src.index)
		}
		untried = append(untried, fmt.Sprintf("FETCH_USE_%d", src.index))
	}
	b.WriteString("FETCH_UNTRIED=$((" + strings.Join(untried, " + ") + "))\n" +
		"FETCH_RATE=0\n" +
		"if [ \"$FETCH_UNTRIED\" -gt 1 ]; then FETCH_RATE=$FETCH_CUT_RATE; fi\n" +
		"FETCH_SPENT=0\n" +
		"FETCH_DONE=0\n" +
		"FETCH_DONE_FILE=\"\"\n" +
		"FETCH_RC=1\n")
	b.WriteString(agentWalkKeptCheck(payload.CompressedSHA256 != ""))
	b.WriteString("if [ \"$FETCH_DONE\" = 0 ] && [ \"$FETCH_UNTRIED\" = 0 ]; then\n" +
		"  echo 'lattice agent update: no download source in this plan works on this node' >&2\n" +
		"  exit 1\n" +
		"fi\n")
	for _, src := range sources {
		fmt.Fprintf(&b, "FETCH_GOT_%d=0\nFETCH_RC_%d=\"\"\n", src.index, src.index)
	}

	// First pass.
	for _, src := range sources {
		fmt.Fprintf(&b, "if [ \"$FETCH_DONE\" = 0 ] && [ \"$FETCH_USE_%d\" = 1 ]; then\n"+
			"  FETCH_LEFT=$((FETCH_BUDGET - FETCH_SPENT))\n"+
			"  if [ \"$FETCH_LEFT\" -ge \"$FETCH_CONNECT\" ]; then\n"+
			"    FETCH_LIMIT=$FETCH_LEFT\n"+
			"    if [ \"$FETCHER\" = curl ]; then FETCH_LIMIT=$((FETCH_LEFT / FETCH_UNTRIED)); fi\n"+
			"    fetch_one %d %s %s %d\n"+
			"    FETCH_GOT_%d=$FETCH_GOT\n"+
			"    FETCH_RC_%d=$FETCH_RC\n"+
			"  fi\n"+
			"  FETCH_UNTRIED=$((FETCH_UNTRIED - 1))\n"+
			"fi\n", src.index, src.index, src.kind, src.file, src.index, src.index, src.index)
	}

	// Second pass, curl only.
	b.WriteString("if [ \"$FETCH_DONE\" = 0 ] && [ \"$FETCHER\" = curl ]; then\n" +
		"  FETCH_BEST=0\n" +
		"  FETCH_BEST_GOT=0\n" +
		"  FETCH_BEST_SIZE=1\n")
	for _, src := range sources {
		// got/size beats best_got/best_size, cross-multiplied so the shell
		// stays in integers. Ties keep the earlier source.
		fmt.Fprintf(&b, "  if [ \"$FETCH_GOT_%d\" -gt 0 ] && [ $((FETCH_GOT_%d * FETCH_BEST_SIZE)) -gt $((FETCH_BEST_GOT * %s)) ]; then\n"+
			"    FETCH_BEST=%d\n"+
			"    FETCH_BEST_GOT=$FETCH_GOT_%d\n"+
			"    FETCH_BEST_SIZE=$((%s))\n"+
			"  fi\n", src.index, src.index, src.size, src.index, src.index, src.size)
	}
	b.WriteString("  FETCH_TRIES=0\n" +
		"  while [ \"$FETCH_BEST\" != 0 ]; do\n" +
		"    FETCH_LEFT=$((FETCH_BUDGET - FETCH_SPENT))\n" +
		"    if [ \"$FETCH_LEFT\" -lt \"$FETCH_CONNECT\" ]; then break; fi\n" +
		"    FETCH_LIMIT=$FETCH_LEFT\n" +
		"    FETCH_RATE=0\n" +
		"    case \"$FETCH_BEST\" in\n")
	for _, src := range sources {
		fmt.Fprintf(&b, "      %d)\n"+
			"        fetch_one %d %s %s p2\n"+
			"        FETCH_RC_%d=$FETCH_RC\n"+
			"        ;;\n", src.index, src.index, src.kind, src.file, src.index)
	}
	b.WriteString("    esac\n" +
		"    if [ \"$FETCH_DONE\" != 0 ]; then break; fi\n" +
		"    FETCH_TRIES=$((FETCH_TRIES + 1))\n" +
		"    if [ \"$FETCH_TRIES\" -gt \"$FETCH_RETRIES\" ]; then break; fi\n" +
		// curl's transient failures: connect, HTTP/2, partial body, timeout,
		// TLS handshake, empty reply, send, receive, HTTP/2 stream.
		"    case \"$FETCH_RC\" in 7|16|18|28|35|52|55|56|92) ;; *) break ;; esac\n" +
		"    if [ $((FETCH_BUDGET - FETCH_SPENT - FETCH_PAUSE)) -lt \"$FETCH_CONNECT\" ]; then break; fi\n" +
		"    sleep \"$FETCH_PAUSE\"\n" +
		"    FETCH_SPENT=$((FETCH_SPENT + FETCH_PAUSE))\n" +
		"  done\n" +
		"fi\n")

	// An incomplete walk: a fetch may have completed a file and still
	// failed, so check the kept files again. Otherwise drop a partial no
	// source could continue, report what is kept, and fail with the last
	// fetch's status.
	b.WriteString("if [ \"$FETCH_DONE\" = 0 ]; then fetch_kept; fi\n")
	b.WriteString("if [ \"$FETCH_DONE\" = 0 ]; then\n")
	for _, file := range agentWalkFiles(sources) {
		var reached, refused []string
		for _, src := range sources {
			if src.file != file {
				continue
			}
			reached = append(reached, fmt.Sprintf("$FETCH_RC_%d", src.index))
			refused = append(refused, fmt.Sprintf("{ [ -z \"$FETCH_RC_%d\" ] || [ \"$FETCH_RC_%d\" = 33 ]; }", src.index, src.index))
		}
		fmt.Fprintf(&b, "  if [ -n \"%s\" ] && %s; then rm -f %s; fi\n", strings.Join(reached, ""), strings.Join(refused, " && "), file)
		label := "download"
		if file == "\"$PACKED\"" {
			label = "compressed download"
		}
		// wget leaves an empty file behind a refused request; an empty
		// partial is nothing to continue.
		fmt.Fprintf(&b, "  if [ -s %s ]; then\n"+
			"    echo \"lattice agent update: download failed; kept the $(fetch_size %s) bytes of the %s received so far for the next attempt to continue\" >&2\n"+
			"  else\n"+
			"    rm -f %s\n"+
			"  fi\n", file, file, label, file)
	}
	b.WriteString("  exit \"$FETCH_RC\"\n" +
		"fi\n")
	return b.String()
}

// agentWalkKeptCheck renders fetch_kept, which finishes the walk when a kept
// file already holds the pinned bytes, and runs it before the first fetch.
// Fetching such a file would not finish it: a range request that starts at
// its end is answered 416, which curl 8 treats as done and curl 7 (Debian 12
// ships 7.88, Ubuntu 22.04 7.81) reports as exit 22, so on those nodes a
// complete kept file, one a later step failed on or one fetched in full by a
// run that was then cut, could never be finished again. The walk runs it once
// more after an incomplete walk, for a file that a fetch completed before
// failing, or that a second-pass range request then found complete. A
// compressed plan pins both sizes, so a kept file of full length that fails
// its digest is dropped as well, rather than asked for a range past its end.
func agentWalkKeptCheck(compressed bool) string {
	var b strings.Builder
	b.WriteString("fetch_sha() {\n" +
		"  if command -v sha256sum >/dev/null 2>&1; then sha256sum \"$1\" | awk '{print $1}'\n" +
		"  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 \"$1\" | awk '{print $1}'\n" +
		"  fi\n" +
		"}\n")
	b.WriteString("fetch_kept() {\n" +
		"  if [ -s \"$CANDIDATE\" ]; then\n" +
		"    if [ \"$(fetch_sha \"$CANDIDATE\")\" = \"$EXPECT_SHA\" ]; then\n" +
		"      FETCH_DONE=kept\n" +
		"      FETCH_DONE_FILE=$CANDIDATE\n")
	if compressed {
		b.WriteString("    elif [ \"$(fetch_size \"$CANDIDATE\")\" -ge \"$EXPECT_SIZE\" ]; then\n" +
			"      rm -f \"$CANDIDATE\"\n")
	}
	b.WriteString("    fi\n" +
		"  fi\n")
	if compressed {
		b.WriteString("  if [ \"$FETCH_DONE\" = 0 ] && [ -s \"$PACKED\" ]; then\n" +
			"    if [ \"$(fetch_sha \"$PACKED\")\" = \"$EXPECT_PACKED_SHA\" ]; then\n" +
			"      FETCH_DONE=kept\n" +
			"      FETCH_DONE_FILE=$PACKED\n" +
			"    elif [ \"$(fetch_size \"$PACKED\")\" -ge \"$EXPECT_PACKED_SIZE\" ]; then\n" +
			"      rm -f \"$PACKED\"\n" +
			"    fi\n" +
			"  fi\n")
	}
	b.WriteString("  if [ \"$FETCH_DONE\" = kept ]; then\n" +
		"    echo \"lattice agent update: $FETCH_DONE_FILE already holds the pinned bytes\"\n" +
		"  fi\n" +
		"}\n" +
		"fetch_kept\n")
	return b.String()
}

// agentWalkFiles lists the partial files the sources write, in order.
func agentWalkFiles(sources []agentFetchSource) []string {
	var out []string
	seen := map[string]bool{}
	for _, src := range sources {
		if !seen[src.file] {
			seen[src.file] = true
			out = append(out, src.file)
		}
	}
	return out
}

func agentWalkCurlLine(src agentFetchSource) string {
	limits := " --connect-timeout \"$FETCH_CONNECT\" --max-time \"$FETCH_LIMIT\" --speed-limit \"$FETCH_RATE\" --speed-time \"$FETCH_CUT_WINDOW\""
	if src.leased {
		return "curl -fsS --proto '=https' --tlsv1.2" + limits + agentFetchCurlLease + " -C - -o " + src.file + " " + src.url
	}
	return "curl -fsSL --proto '=https' --tlsv1.2 --proto-redir '=https'" + limits + " -C - -o " + src.file + " " + src.url
}

func agentWalkWgetLine(src agentFetchSource) string {
	if src.leased {
		return "fetch_bounded wget --https-only -q --max-redirect=0" + agentFetchWgetTimeouts + agentFetchWgetLease + " -c -O " + src.file + " " + src.url
	}
	return "fetch_bounded wget --https-only -q" + agentFetchWgetTimeouts + " -c -O " + src.file + " " + src.url
}

// agentUpdateUnpackStep turns a finished compressed download into the
// candidate binary. The compressed bytes are held to their digest before
// anything decompresses them, so unverified input never reaches a
// decompressor running as root. Decompression stops one byte past the pinned
// size, so a file that would expand further cannot fill the disk, and any
// size other than the pinned one is refused. The result is then held to the
// binary's own digest by the step that follows, as every download is.
func agentUpdateUnpackStep(compressed bool) string {
	if !compressed {
		return ""
	}
	return "if [ \"$FETCH_DONE_FILE\" = \"$PACKED\" ]; then\n" +
		"  FETCH_STAGE=verify\n" +
		"  if command -v sha256sum >/dev/null 2>&1; then\n" +
		"    ACTUAL_PACKED_SHA=$(sha256sum \"$PACKED\" | awk '{print $1}')\n" +
		"  elif command -v shasum >/dev/null 2>&1; then\n" +
		"    ACTUAL_PACKED_SHA=$(shasum -a 256 \"$PACKED\" | awk '{print $1}')\n" +
		"  else\n" +
		"    echo 'lattice agent update: sha256sum or shasum is required' >&2\n" +
		"    exit 1\n" +
		"  fi\n" +
		"  if [ \"$ACTUAL_PACKED_SHA\" != \"$EXPECT_PACKED_SHA\" ]; then\n" +
		"    rm -f \"$PACKED\"\n" +
		"    echo \"lattice agent update: compressed sha256 mismatch expected=$EXPECT_PACKED_SHA actual=$ACTUAL_PACKED_SHA; deleted the compressed download without decompressing it, so the next attempt starts over\" >&2\n" +
		"    exit 1\n" +
		"  fi\n" +
		"  FETCH_STAGE=unpack\n" +
		"  rm -f \"$CANDIDATE\"\n" +
		"  gzip -dc <\"$PACKED\" | head -c $((EXPECT_SIZE + 1)) >\"$CANDIDATE\"\n" +
		"  FETCH_UNPACKED=$(fetch_size \"$CANDIDATE\")\n" +
		"  if [ \"$FETCH_UNPACKED\" != \"$EXPECT_SIZE\" ]; then\n" +
		"    rm -f \"$CANDIDATE\" \"$PACKED\"\n" +
		"    echo \"lattice agent update: the compressed download decompressed to $FETCH_UNPACKED bytes, where decompression stops at $((EXPECT_SIZE + 1)), not the $EXPECT_SIZE bytes the plan pins; deleted it so the next attempt starts over\" >&2\n" +
		"    exit 1\n" +
		"  fi\n" +
		"fi\n"
}

// agentUpdateWalkDigestMismatchStep is agentUpdateDigestMismatchStep for the
// walk. When the binary came out of the compressed download, that download
// goes too: it verified, so it would decompress to the same wrong bytes.
func agentUpdateWalkDigestMismatchStep(compressed bool) string {
	drop := ""
	if compressed {
		drop = "  if [ \"$FETCH_DONE_FILE\" = \"$PACKED\" ]; then rm -f \"$PACKED\"; fi\n"
	}
	return "if [ \"$ACTUAL_SHA\" != \"$EXPECT_SHA\" ]; then\n" +
		"  rm -f \"$CANDIDATE\"\n" +
		drop +
		"  echo \"lattice agent update: sha256 mismatch expected=$EXPECT_SHA actual=$ACTUAL_SHA; deleted the download so the next attempt starts over\" >&2\n" +
		"  exit 1\n" +
		"fi\n"
}

// agentUpdateWalkInstalledStep removes the kept downloads once the binary's
// copy is in place.
func agentUpdateWalkInstalledStep(compressed bool) string {
	if compressed {
		return "rm -f \"$CANDIDATE\" \"$PACKED\"\n"
	}
	return "rm -f \"$CANDIDATE\"\n"
}

var (
	agentFetchEntryRe  = regexp.MustCompile(`^(?:[1-9]|p2):(?:cp|cp\.gz|up):[0-9]{1,3}:[0-9]{1,12}:(?:[0-9]{1,6}|-)$`)
	agentFetchResultRe = regexp.MustCompile(`^result:[0-9]{1,3}:[a-z]{1,16}$`)
)

// agentFetchSummaryMaxFields bounds what one summary line may carry: four
// first-pass fetches, four second-pass fetches and the result.
const agentFetchSummaryMaxFields = 9

// parseAgentFetchSummary returns the last lattice-agent-fetch line in a task's
// output, re-assembled from fields that each passed a strict pattern, and the
// same fields as the record the update policy keeps as last_fetch. The
// output comes from the node, so nothing else from it is kept. The record
// carries no approval, version or time; the caller knows those.
func parseAgentFetchSummary(output string) (string, model.AgentUpdateFetch, bool) {
	lines := strings.Split(output, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		rest, ok := strings.CutPrefix(line, agentFetchSummaryPrefix+" ")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 || len(fields) > agentFetchSummaryMaxFields {
			return "", model.AgentUpdateFetch{}, false
		}
		var record model.AgentUpdateFetch
		for _, field := range fields[:len(fields)-1] {
			attempt, ok := parseAgentFetchEntry(field)
			if !ok {
				return "", model.AgentUpdateFetch{}, false
			}
			record.Fetches = append(record.Fetches, attempt)
		}
		last := fields[len(fields)-1]
		if !agentFetchResultRe.MatchString(last) {
			return "", model.AgentUpdateFetch{}, false
		}
		// result:<exit>:<stage>, both already held to the pattern.
		parts := strings.Split(last, ":")
		record.ExitCode, _ = strconv.Atoi(parts[1])
		record.Stage = parts[2]
		return agentFetchSummaryPrefix + " " + strings.Join(fields, " "), record, true
	}
	return "", model.AgentUpdateFetch{}, false
}

// parseAgentFetchEntry reads one index:kind:exit:bytes:seconds field. The
// pattern bounds every number well inside its type, so the conversions
// cannot fail once it matches.
func parseAgentFetchEntry(field string) (model.AgentUpdateFetchAttempt, bool) {
	if !agentFetchEntryRe.MatchString(field) {
		return model.AgentUpdateFetchAttempt{}, false
	}
	parts := strings.Split(field, ":")
	var attempt model.AgentUpdateFetchAttempt
	if parts[0] == "p2" {
		attempt.SecondPass = true
	} else {
		attempt.Source, _ = strconv.Atoi(parts[0])
	}
	attempt.Kind = parts[1]
	attempt.ExitCode, _ = strconv.Atoi(parts[2])
	attempt.Bytes, _ = strconv.ParseInt(parts[3], 10, 64)
	if parts[4] != "-" {
		seconds, _ := strconv.ParseInt(parts[4], 10, 64)
		attempt.Seconds = &seconds
	}
	return attempt, true
}
