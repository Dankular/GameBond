// Package procjob is process_job.py: a Windows job object whose handle closing
// (including by this process dying) kills every assigned child.
package procjob

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObject    = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJob  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJob = kernel32.NewProc("AssignProcessToJobObject")
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x2000
	processSetQuota                   = 0x0100
	processTerminate                  = 0x0001
)

// extendedLimits mirrors JOBOBJECT_EXTENDED_LIMIT_INFORMATION (64-bit layout
// uses the same field widths as the Python ctypes structure).
type extendedLimits struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
	IO                      [6]uint64
	ProcessMemoryLimit      uintptr
	JobMemoryLimit          uintptr
	PeakProcessMemoryUsed   uintptr
	PeakJobMemoryUsed       uintptr
}

// Job owns a kill-on-close job object.
type Job struct{ handle syscall.Handle }

// New creates a job whose children die when it is closed.
func New() (*Job, error) {
	h, _, err := procCreateJobObject.Call(0, 0)
	if h == 0 {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}
	var limits extendedLimits
	limits.LimitFlags = jobObjectLimitKillOnJobClose
	r, _, err := procSetInformationJob.Call(h, jobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	if r == 0 {
		syscall.CloseHandle(syscall.Handle(h))
		return nil, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	return &Job{handle: syscall.Handle(h)}, nil
}

// Add assigns the process with this pid to the job.
func (j *Job) Add(pid int) error {
	if j.handle == 0 {
		return fmt.Errorf("job closed")
	}
	p, err := syscall.OpenProcess(processSetQuota|processTerminate, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer syscall.CloseHandle(p)
	r, _, err := procAssignProcessToJob.Call(uintptr(j.handle), uintptr(p))
	if r == 0 {
		return fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	return nil
}

// Close closes the job handle, which terminates every assigned process.
func (j *Job) Close() error {
	if j.handle == 0 {
		return nil
	}
	err := syscall.CloseHandle(j.handle)
	j.handle = 0
	return err
}
