package cli

import (
	"strconv"
	"strings"
)

type ParseWarning struct {
	File    string `json:"file"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

type ParseOptions struct {
	Strict   bool
	Warnings []ParseWarning
}

type Options struct {
	Files        []string
	JSONOutput   bool
	PolicyFile   string
	Strict       bool
	Format       string // text, json, sarif, junit, markdown, patch
	Interactive  bool
	WebServer    bool
	WebPort      int
	NoPager      bool
	Convert      bool
	TargetFormat string // cyclonedx, cdx, spdx, syft
	OutputFile   string
}

func DefaultParseOptions() ParseOptions {
	return ParseOptions{
		Strict:   false,
		Warnings: []ParseWarning{},
	}
}

func (p *ParseOptions) AddWarning(file, message, field string) {
	p.Warnings = append(p.Warnings, ParseWarning{
		File:    file,
		Message: message,
		Field:   field,
	})
}

func ParseArgs(args []string) Options {
	opts := Options{
		Strict: false,
		Format: "text",
	}

	if len(args) > 1 && args[1] == "convert" {
		opts.Convert = true
		args = append(args[:1], args[2:]...) // remove "convert" from args
	}

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--json":
			opts.JSONOutput = true
			opts.Format = "json"
		case "--strict":
			opts.Strict = true
		case "--tolerant":
			opts.Strict = false
		case "--policy":
			if i+1 < len(args) {
				opts.PolicyFile = args[i+1]
				i++
			}
		case "--format", "-f":
			if i+1 < len(args) {
				opts.Format = args[i+1]
				if opts.Format == "json" {
					opts.JSONOutput = true
				}
				i++
			}
		case "--to":
			if i+1 < len(args) {
				opts.TargetFormat = args[i+1]
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				opts.OutputFile = args[i+1]
				i++
			}
		case "--interactive", "-i":
			opts.Interactive = true
		case "--no-pager":
			opts.NoPager = true
		case "-web", "--web":
			opts.WebServer = true
		case "--port":
			if i+1 < len(args) {
				port, _ := strconv.Atoi(args[i+1])
				opts.WebPort = port
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				opts.Files = append(opts.Files, args[i])
			}
		}
	}

	return opts
}
