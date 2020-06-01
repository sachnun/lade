package cmd

import (
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/docker/docker/pkg/term"
	"github.com/lade-io/go-lade"
	"github.com/spf13/cobra"
	"gopkg.in/AlecAivazis/survey.v1"
)

var runCmd = func() *cobra.Command {
	var appName string
	opts := &lade.ProcessCreateOpts{}
	cmd := &cobra.Command{
		Use:   "run <command>",
		Short: "Run command on app",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := getClient()
			if err != nil {
				return err
			}
			if len(args) > 0 {
				opts.Command = args[0]
			}
			return runRun(client, opts, appName)
		},
	}
	cmd.Flags().StringVarP(&appName, "app", "a", "", "App Name")
	cmd.Flags().StringVarP(&opts.PlanID, "plan", "p", "", "Plan")
	return cmd
}()

func runRun(client *lade.Client, opts *lade.ProcessCreateOpts, appName string) error {
	if err := askSelect("App Name:", getAppName, client, getAppOptions, &appName); err != nil {
		return err
	}
	if err := askInput("Command:", "", &opts.Command, survey.Required); err != nil {
		return err
	}
	process, err := client.Process.Create(appName, opts)
	if err != nil {
		return err
	}
	resizeTTY := func() {
		opts := &lade.ProcessResizeOpts{Height: 24, Width: 80}
		size, err := term.GetWinsize(os.Stdin.Fd())
		if err == nil {
			opts.Height = uint(size.Height)
			opts.Width = uint(size.Width)
		}
		client.Process.Resize(appName, process.Number, opts)
	}
	return client.Process.Attach(appName, process.Number, attachStream(resizeTTY))
}

func attachStream(resizeTTY func()) lade.ConnHandler {
	return func(conn net.Conn) error {
		resizeTTY()
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGWINCH)
		go func() {
			for range sigChan {
				resizeTTY()
			}
		}()

		state, err := term.SetRawTerminal(os.Stdin.Fd())
		if err != nil {
			return err
		}
		defer term.RestoreTerminal(os.Stdin.Fd(), state)

		errChan := make(chan error)
		doneChan := make(chan struct{})
		go func() {
			_, err := io.Copy(os.Stdout, conn)
			if err != nil {
				errChan <- err
			}
			close(doneChan)
		}()
		go func() {
			_, err := io.Copy(conn, os.Stdin)
			if err != nil {
				errChan <- err
			}
			conn.Close()
		}()

		select {
		case err = <-errChan:
			if !errors.Is(err, io.EOF) {
				return err
			}
		case <-doneChan:
		}
		return nil
	}
}
