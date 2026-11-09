package procjob

import (
	"os/exec"
	"testing"
	"time"
)

func start(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("ping", "-n", "60", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	return cmd
}

func waits(cmd *exec.Cmd) chan struct{} {
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	return done
}

func TestCloseKillsAssignedChildOnly(t *testing.T) {
	inJob, outside := start(t), start(t)
	j, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Add(inJob.Process.Pid); err != nil {
		t.Fatal(err)
	}
	doneIn, doneOut := waits(inJob), waits(outside)
	select {
	case <-doneIn:
		t.Fatal("child exited before the job closed")
	case <-time.After(300 * time.Millisecond):
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-doneIn:
	case <-time.After(5 * time.Second):
		t.Fatal("closing the job did not kill its child")
	}
	select {
	case <-doneOut:
		t.Fatal("a process outside the job was killed")
	case <-time.After(300 * time.Millisecond):
	}
	if err := j.Close(); err != nil {
		t.Fatal("second Close:", err)
	}
	if err := j.Add(inJob.Process.Pid); err == nil {
		t.Fatal("Add on a closed job succeeded")
	}
}

func TestAddUnknownPid(t *testing.T) {
	j, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.Add(0x7ffffff0); err == nil {
		t.Fatal("unknown pid accepted")
	}
}
