package misc

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
)

func GetPassword() (password string, err error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Password: ")
	err = SetTermEcho(false)
	if err != nil {
		return
	}
	password, err = reader.ReadString('\n')
	fmt.Println()
	err = SetTermEcho(true)
	return
}

// Useful for asking passwords silently
// TODO: This needs Windows implementation too
func SetTermEcho(on bool) (err error) {
	attrs := syscall.ProcAttr{
		Dir:   "",
		Env:   []string{},
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
		Sys:   nil,
	}
	var echo string
	if on {
		echo = "echo"
	} else {
		echo = "-echo"
	}
	var ws syscall.WaitStatus
	pid, err := syscall.ForkExec("/bin/stty", []string{"stty", echo}, &attrs)
	if err != nil {
		return
	}
	_, err = syscall.Wait4(pid, &ws, 0, nil)
	return
}
