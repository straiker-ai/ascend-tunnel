//go:build !windows && !darwin && !linux

package service

import (
	"context"
	"errors"
	"io"
)

// Kind says what Install sets up, for its summary.
const Kind = "nothing: not supported on this system"

var errUnsupported = errors.New("service install supports Windows, macOS and Linux: run ascend-tunnel under your own service manager")

func Install(Spec, io.Writer) error                      { return errUnsupported }
func Uninstall(io.Writer) error                          { return errUnsupported }
func Status() (string, error)                            { return "", errUnsupported }
func RunIfService(func(context.Context) int) (int, bool) { return 0, false }
