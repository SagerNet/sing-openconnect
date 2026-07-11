package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"slices"
)

var (
	expectedArgumentsBase64 string
	expectedAppVersion      string
	wrapperReportBase64     string
	wrapperBehavior         string
)

func main() {
	expectedArgumentsContent, err := base64.StdEncoding.DecodeString(expectedArgumentsBase64)
	if err != nil {
		os.Exit(29)
	}
	var expectedArguments []string
	err = json.Unmarshal(expectedArgumentsContent, &expectedArguments)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "invalid M2_GP_WRAPPER_ARGUMENTS")
		os.Exit(30)
	}
	if !slices.Equal(os.Args[1:], expectedArguments) {
		_, _ = fmt.Fprintln(os.Stderr, "unexpected wrapper arguments")
		os.Exit(31)
	}
	if os.Getenv("APP_VERSION") != expectedAppVersion {
		_, _ = fmt.Fprintln(os.Stderr, "unexpected APP_VERSION")
		os.Exit(32)
	}
	switch wrapperBehavior {
	case "nonzero":
		os.Exit(33)
	case "abnormal":
		process, processErr := os.FindProcess(os.Getpid())
		if processErr != nil {
			os.Exit(34)
		}
		processErr = process.Kill()
		if processErr != nil {
			os.Exit(35)
		}
		select {}
	}
	report, err := base64.StdEncoding.DecodeString(wrapperReportBase64)
	if err != nil {
		os.Exit(36)
	}
	_, err = os.Stdout.Write(report)
	if err != nil {
		os.Exit(37)
	}
}
