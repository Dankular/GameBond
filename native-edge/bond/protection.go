package bond

import (
	"fmt"
	"math"
)

// Protection presets set how early the sender adds redundancy to bulk traffic.
// They move the loss levels at which parity and duplication start; steering off
// a very lossy path is unaffected.
//
//	off     no parity or duplication
//	low     parity from 0.5% loss, duplication from 3%
//	normal  parity from 0.3%, duplication from 1.5%  (default)
//	high    parity from 0.1%, duplication from 0.5%
//	tcp     as high, and every TCP data packet is also copied onto a second path
//	        (UDP, such as games and voice, keeps the loss-triggered tiers)
//	auto    cheap cover: TCP data in parity groups (about 1/8 extra), small packets
//	        (ACKs, handshakes, games, voice) copied, full duplication only when a
//	        path is failing, silent or hinted
//	max     bulk is always duplicated while two paths are ready
type protectionPreset struct{ fec, dup float64 }

var protectionPresets = map[string]protectionPreset{
	"off":    {math.Inf(1), math.Inf(1)},
	"low":    {0.005, 0.03},
	"normal": {fecRatio, dupRatio},
	"high":   {0.001, 0.005},
	"tcp":    {0.001, 0.005},
	"auto":   {0.001, 0.005},
	"max":    {0, 0},
}

// SetProtection selects a preset; the empty string means "normal".
func (s *Sender) SetProtection(name string) error {
	if name == "" {
		name = "normal"
	}
	p, ok := protectionPresets[name]
	if !ok {
		return fmt.Errorf("unknown protection %q (off, low, normal, high, tcp, auto, max)", name)
	}
	s.protectName, s.fecAt, s.dupAt = name, p.fec, p.dup
	return nil
}

// ProtectionName reports the active preset.
func (s *Sender) ProtectionName() string {
	if s.protectName == "" {
		return "normal"
	}
	return s.protectName
}

func (s *Sender) thresholds() (fec, dup float64) {
	if s.protectName == "" {
		return fecRatio, dupRatio
	}
	return s.fecAt, s.dupAt
}
