package desktopruntime

import (
	"os"
	"os/exec"
)

func spawnSupervisor(p Plan) (int, error) {
	if err := os.MkdirAll(Resolve(p.Root, ".runtime"), 0700); err != nil {
		return 0, err
	}
	log, err := os.OpenFile(Resolve(p.Root, ".runtime/supervisor.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return 0, err
	}
	defer log.Close()
	cmd := exec.Command(p.Client, p.Args()...)
	cmd.Dir = p.Root
	cmd.Stdout = log
	cmd.Stderr = log
	hideSupervisor(cmd)
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	go cmd.Wait()
	return cmd.Process.Pid, nil
}
