//go:build !windows

// Package procjob is process_job.py; job objects exist only on Windows.
package procjob

import "errors"

type Job struct{}

func New() (*Job, error)     { return nil, errors.New("job objects need Windows") }
func (j *Job) Add(int) error { return errors.New("job objects need Windows") }
func (j *Job) Close() error  { return nil }
