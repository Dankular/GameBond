package bond

const replayWidth = 8192

// ReplayWindow accepts unique out-of-order packets within the GB03 window.
// Its owner serializes access together with the peer's authenticated state.
type ReplayWindow struct {
	highest     uint64
	initialized bool
	bits        [replayWidth / 64]uint64
}

func (w *ReplayWindow) Accept(sequence uint64) bool {
	if !w.initialized {
		w.initialized = true
		w.highest = sequence
		w.bits[0] = 1
		return true
	}
	if sequence > w.highest {
		shift := sequence - w.highest
		if shift >= replayWidth {
			w.bits = [replayWidth / 64]uint64{}
		} else {
			words, bits := int(shift/64), uint(shift%64)
			for i := len(w.bits) - 1; i >= 0; i-- {
				var value uint64
				j := i - words
				if j >= 0 {
					value = w.bits[j] << bits
					if bits > 0 && j > 0 {
						value |= w.bits[j-1] >> (64 - bits)
					}
				}
				w.bits[i] = value
			}
		}
		w.highest = sequence
		w.bits[0] |= 1
		return true
	}
	age := w.highest - sequence
	if age >= replayWidth {
		return false
	}
	word, bit := int(age/64), uint(age%64)
	mask := uint64(1) << bit
	if w.bits[word]&mask != 0 {
		return false
	}
	w.bits[word] |= mask
	return true
}
