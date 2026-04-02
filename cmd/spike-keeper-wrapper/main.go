package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

func main() {
	cmd := exec.Command("/keeper", os.Args[1:]...)
	cmd.Env = os.Environ()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "spike-keeper-wrapper: stdout pipe failed: %v\n", err)
		os.Exit(1)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "spike-keeper-wrapper: stderr pipe failed: %v\n", err)
		os.Exit(1)
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "spike-keeper-wrapper: start failed: %v\n", err)
		os.Exit(1)
	}

	done := make(chan struct{}, 2)
	go streamFiltered(stdout, os.Stdout, done)
	go streamFiltered(stderr, os.Stderr, done)
	<-done
	<-done

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "spike-keeper-wrapper: wait failed: %v\n", err)
		os.Exit(1)
	}
}

func streamFiltered(src io.Reader, dst io.Writer, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()

	scanner := bufio.NewScanner(src)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if shouldSuppressKeeperLog(line) {
			continue
		}
		fmt.Fprintln(dst, line)
	}
}

func shouldSuppressKeeperLog(line string) bool {
	return strings.Contains(line, `"msg":"RequestBody"`) &&
		strings.Contains(line, `"code":"fs_stream_close_failed"`)
}
