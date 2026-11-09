package scanner

import (
	"context"
	"errors"
	"sync"
)

// ProbeResult is one ICMP probe outcome.
type ProbeResult struct {
	Address   string `json:"address"`
	Responded bool   `json:"responded"`
	Status    any    `json:"status"`
	RTTMS     *int   `json:"rtt_ms"`
}

// Probe sends one source-bound ICMP echo.
type Probe func(source, target string, timeoutMS int) (ProbeResult, error)

// DiscoveryJob is a bounded active scan; Start is the only active entry point.
type DiscoveryJob struct {
	Subnet         string
	Source         string
	InterfaceIndex int
	Targets        []string
	workers        int
	timeoutMS      int
	probe          Probe

	mu         sync.Mutex
	started    bool
	state      string
	results    []ProbeResult
	errors     []string
	startedAt  float64
	finishedAt float64
	cancel     context.CancelFunc
	ctx        context.Context
	done       chan struct{}
	revalidate func() ([]Adapter, error)
}

// NewDiscoveryJob validates the scan. adapters may be nil when inventory is
// supplied through revalidate (then it is re-checked again at Start).
func NewDiscoveryJob(subnet, source string, interfaceIndex int, adapters []Adapter, revalidate func() ([]Adapter, error), workers, timeoutMS, maxHosts int, probe Probe) (*DiscoveryJob, error) {
	if interfaceIndex <= 0 {
		return nil, errors.New("Choose a valid local adapter")
	}
	if workers < 1 || workers > 16 || timeoutMS < 50 || timeoutMS > 1500 {
		return nil, errors.New("Invalid discovery concurrency or timeout")
	}
	if adapters == nil {
		if revalidate == nil {
			return nil, errors.New("no adapter inventory")
		}
		var err error
		if adapters, err = revalidate(); err != nil {
			return nil, err
		}
	}
	src, targets, err := ValidateScan(subnet, source, interfaceIndex, adapters, maxHosts)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &DiscoveryJob{Subnet: subnet, Source: src, InterfaceIndex: interfaceIndex, Targets: targets, workers: workers, timeoutMS: timeoutMS,
		probe: probe, state: "ready", ctx: ctx, cancel: cancel, done: make(chan struct{}), revalidate: revalidate}, nil
}

// Start begins probing once; a second call fails.
func (j *DiscoveryJob) Start(adaptersWereSupplied bool) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.started {
		return errors.New("This discovery job has already been started")
	}
	if !adaptersWereSupplied && j.revalidate != nil {
		// Re-check at execution time so an old dialog cannot scan from an adapter that went down.
		adapters, err := j.revalidate()
		if err != nil {
			return err
		}
		if _, _, err := ValidateScan(j.Subnet, j.Source, j.InterfaceIndex, adapters, 256); err != nil {
			return err
		}
	}
	j.started, j.state, j.startedAt = true, "running", Now()
	go j.run()
	return nil
}

func (j *DiscoveryJob) Cancel() { j.cancel() }

// Wait blocks until the job finishes.
func (j *DiscoveryJob) Wait() { <-j.done }

// Snapshot is the status document for the UI.
type Snapshot struct {
	State          string        `json:"state"`
	Subnet         string        `json:"subnet"`
	SourceAddress  string        `json:"source_address"`
	InterfaceIndex int           `json:"interface_index"`
	Total          int           `json:"total"`
	Completed      int           `json:"completed"`
	Results        []ProbeResult `json:"results"`
	Errors         []string      `json:"errors"`
	StartedAt      *float64      `json:"started_at"`
	FinishedAt     *float64      `json:"finished_at"`
	ActiveProbe    bool          `json:"active_probe"`
	Limitations    []string      `json:"limitations"`
}

func (j *DiscoveryJob) Snapshot() Snapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	s := Snapshot{State: j.state, Subnet: j.Subnet, SourceAddress: j.Source, InterfaceIndex: j.InterfaceIndex, Total: len(j.Targets), Completed: len(j.results),
		Results: append([]ProbeResult{}, j.results...), Errors: append([]string{}, j.errors...), ActiveProbe: true,
		Limitations: []string{"Non-responsive devices can still be online or block ICMP.", "Discovery sends one source-bound ICMP request per selected local address."}}
	if j.started {
		v := j.startedAt
		s.StartedAt = &v
	}
	if j.finishedAt != 0 {
		v := j.finishedAt
		s.FinishedAt = &v
	}
	return s
}

func (j *DiscoveryJob) run() {
	defer close(j.done)
	targets := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < j.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targets {
				if j.ctx.Err() != nil {
					return
				}
				res, err := func() (r ProbeResult, err error) {
					defer func() {
						if p := recover(); p != nil {
							err = errors.New("probe panicked")
						}
					}()
					return j.probe(j.Source, t, j.timeoutMS)
				}()
				j.mu.Lock()
				if err != nil {
					j.results = append(j.results, ProbeResult{Address: t, Status: "error"})
					if len(j.errors) < 16 {
						j.errors = append(j.errors, err.Error())
					}
				} else {
					j.results = append(j.results, res)
				}
				j.mu.Unlock()
			}
		}()
	}
feed:
	for _, t := range j.Targets {
		if j.ctx.Err() != nil {
			break feed
		}
		select {
		case <-j.ctx.Done():
			break feed
		case targets <- t:
		}
	}
	close(targets)
	wg.Wait()
	j.mu.Lock()
	if j.ctx.Err() != nil {
		j.state = "cancelled"
	} else {
		j.state = "completed"
	}
	j.finishedAt = Now()
	j.mu.Unlock()
}
