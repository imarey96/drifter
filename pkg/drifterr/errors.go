// Package drifterr defines typed, user-facing errors. Every error that can
// reach a human carries a short message and an actionable hint.
package drifterr

import (
	"errors"
	"fmt"
)

type Code string

const (
	CodeBinaryNotFound Code = "binary_not_found"
	CodeCredentials    Code = "missing_credentials"
	CodeHCLSyntax      Code = "hcl_syntax"
	CodeConfigInvalid  Code = "config_invalid"
	CodeNotInitialized Code = "not_initialized"
	CodePlanFailed     Code = "plan_failed"
	CodeNoScan         Code = "no_scan_results"
	CodeInvalidInput   Code = "invalid_input"
)

type Error struct {
	Code   Code
	Msg    string
	Hint   string
	Detail string // scrubbed tool output, safe to print
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Msg, e.Err)
	}
	return e.Msg
}

func (e *Error) Unwrap() error { return e.Err }

func New(code Code, msg, hint string) *Error {
	return &Error{Code: code, Msg: msg, Hint: hint}
}

func Wrap(code Code, err error, msg, hint string) *Error {
	return &Error{Code: code, Msg: msg, Hint: hint, Err: err}
}

// As extracts a *Error from an error chain.
func As(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}
