package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"gamebond.local/nativeedge/client"
)

// metricsLog is the transport's flight recorder: one JSON line per sample with
// every path's rate, delay and feedback health plus the loss, repair, protection
// and queue counters. It exists so a regression (feedback refused, a link stuck
// at a rate, losses clustering with skipped copies) shows up in the history
// instead of being noticed by eye. The file rotates at maxBytes into one backup.
type metricsLog struct {
	path     string
	maxBytes int64
}

const metricsMaxBytes = 16 << 20

func newMetricsLog(path string) *metricsLog {
	return &metricsLog{path: path, maxBytes: metricsMaxBytes}
}

// pathMetrics is one path's row; Budget carries the rate controller's view.
type pathMetrics struct {
	Slot            int            `json:"slot"`
	Ready           bool           `json:"ready"`
	Suspect         bool           `json:"suspect"`
	RTTMS           float64        `json:"rtt_ms"`
	JitterMS        float64        `json:"jitter_ms"`
	WireTX          uint64         `json:"wire_tx"`
	WireRX          uint64         `json:"wire_rx"`
	BFDState        any            `json:"bfd_state"`
	BFDDowns        any            `json:"bfd_downs"`
	FeedbackTimeout float64        `json:"feedback_timeout"`
	Loss            float64        `json:"loss"`
	Budget          map[string]any `json:"budget"`
}

type metricsRecord struct {
	T       float64                 `json:"t"`
	Ready   int                     `json:"ready"`
	Paths   []pathMetrics           `json:"paths"`
	Reorder bond.ReorderStats       `json:"reorder"`
	Send    bond.SenderStats        `json:"send"`
	Receive bond.ReceiverStats      `json:"receive"`
	Queue   bond.TransmitQueueStats `json:"queue"`
	Alarms  []bond.Alarm            `json:"alarms,omitempty"`
}

// budgetKeys are the rate-controller fields kept per sample.
var budgetKeys = []string{"rate_mbps", "delivery_rate_mbps", "max_rate_mbps", "queue_delay_ms", "srtt_ms", "window_bytes", "inflight_bytes",
	"pending_packets", "acked_packets", "expired_packets", "invalid_acks", "backoffs", "delay_backoffs", "timeout_backoffs", "rate_increases", "settled_loss_ratio"}

func metricsSample(s client.Snapshot, now time.Time, alarms []bond.Alarm) metricsRecord {
	quality, _ := s.QoS["path_quality"].([]bond.PathQuality)
	rec := metricsRecord{T: float64(now.UnixNano()) / 1e9, Ready: s.Ready, Reorder: s.Reorder, Send: s.Sender, Receive: s.Receiver, Queue: s.Queue, Alarms: alarms}
	for i, p := range s.Paths {
		row := pathMetrics{Slot: p.Local, Ready: p.Ready, Suspect: p.Suspect, RTTMS: p.RTTMilliseconds, JitterMS: p.JitterMilliseconds,
			WireTX: p.WireTX, WireRX: p.WireRX, BFDState: p.BFD["state"], BFDDowns: p.BFD["downs"], Budget: map[string]any{}}
		for _, k := range budgetKeys {
			if v, ok := p.Budget[k]; ok {
				row.Budget[k] = v
			}
		}
		if i < len(quality) {
			row.FeedbackTimeout, row.Loss = quality[i].FeedbackTimeoutRatio, quality[i].Loss
		}
		rec.Paths = append(rec.Paths, row)
	}
	return rec
}

// Append writes one record, rotating first when the file is full.
func (m *metricsLog) Append(rec metricsRecord) error {
	if m == nil || m.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	if info, err := os.Stat(m.path); err == nil && info.Size() >= m.maxBytes {
		_ = os.Remove(m.path + ".1")
		if err := os.Rename(m.path, m.path+".1"); err != nil {
			return err
		}
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(m.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}
