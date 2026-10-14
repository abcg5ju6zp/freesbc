package shield

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/freesbc/freesbc/internal/config"
)

// Generation is the identity of the shield rule set a piece of live
// security state was created under. It is a deterministic SHA-256 over the
// parsed (not textual) shield values that shape persisted state — ban
// duration, the public and carrier rate limits, and the two strike
// thresholds — so the same rules after a restart, or equivalent spellings
// ("10/10m" and "10/600s"), share a generation, while editing any of them
// starts a new one. max_sessions and invite_rate_limit are excluded: their
// state is not kept in the shield and is not snapshotted.
//
// State created under an older generation keeps being enforced under the
// rules (and deadlines) it was born with until it naturally expires; a
// rules reload never re-interprets or rewrites it.
type Generation string

// generationLen is how many hex chars the admin surfaces show; the full
// 64 are stored on disk and compared internally.
const generationLen = 12

// Short is the display form of a generation.
func (g Generation) Short() string {
	s := string(g)
	if len(s) > generationLen {
		return s[:generationLen]
	}
	return s
}

// GenerationOf computes the rule generation of cfg's shield section.
func GenerationOf(cfg *config.Config) Generation {
	if cfg == nil {
		return ""
	}
	sh := cfg.Shield
	rl, _ := config.ParseRateLimit(sh.RateLimit)
	crl, _ := config.ParseRateLimit(sh.CarrierRateLimit)
	reg, _ := config.ParseStrikeLimit(sh.RegisterBan)
	adm, _ := config.ParseStrikeLimit(sh.AdmissionBan)

	var b strings.Builder
	b.WriteString("ban=")
	b.WriteString(strconv.FormatInt(int64(sh.Ban.Std()), 10))
	b.WriteByte('\n')
	writeRate(&b, "rate=", rl)
	writeRate(&b, "carrier=", crl)
	writeStrike(&b, "register=", reg)
	writeStrike(&b, "admission=", adm)
	sum := sha256.Sum256([]byte(b.String()))
	return Generation(hex.EncodeToString(sum[:]))
}

func writeRate(b *strings.Builder, prefix string, rl config.RateLimit) {
	b.WriteString(prefix)
	b.WriteString(strconv.Itoa(rl.Rate))
	b.WriteByte('/')
	b.WriteString(strconv.FormatInt(int64(rl.Interval), 10))
	b.WriteByte('/')
	b.WriteString(strconv.FormatBool(rl.PerIP))
	b.WriteByte('\n')
}

func writeStrike(b *strings.Builder, prefix string, lim config.StrikeLimit) {
	b.WriteString(prefix)
	if lim.Off {
		b.WriteString("off\n")
		return
	}
	b.WriteString(strconv.Itoa(lim.N))
	b.WriteByte('/')
	b.WriteString(strconv.FormatInt(int64(lim.Window), 10))
	b.WriteByte('\n')
}
