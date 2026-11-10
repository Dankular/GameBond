package stackio

import (
	"sync"
	"testing"
	"time"

	"gamebond.local/nativeedge/bond"
)

type sinkUplink struct{}

func (sinkUplink) Submit(bond.QueuedPacket) bool { return true }

// A console's LAN goroutine and the stack pump both call Send; the classifier
// caches are plain maps, so unserialised callers die with "concurrent map writes".
func TestConcurrentSendDoesNotRaceTheClassifier(t *testing.T) {
	cl, err := bond.NewClassifier(nil, []uint16{3075}, bond.DefaultQoSSettings())
	if err != nil {
		t.Fatal(err)
	}
	b := &Bridge{Uplink: sinkUplink{}, Classifier: cl, TTL: time.Second}
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20000; i++ {
				p := make([]byte, 40)
				p[0], p[9] = 0x45, 17
				p[3] = 40
				p[12], p[13], p[14], p[15] = 10, 77, 0, byte(2+g)
				p[16], p[17], p[18], p[19] = 51, 103, byte(i>>8), byte(i)
				p[20], p[21] = byte(i>>8), byte(i)
				p[22], p[23] = 0x0b, 0xc2
				p[24], p[25] = 0, 20
				b.Send(p)
			}
		}(g)
	}
	wg.Wait()
}
