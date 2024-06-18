// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package containerutils holds multiple utils functions around Container IDs and their patterns
package containerutils

import (
	"regexp"
	"strings"

	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
)

// ContainerIDPatternStr defines the regexp used to match container IDs
// ([0-9a-fA-F]{64}) is standard container id used pretty much everywhere, length: 64
// ([0-9a-fA-F]{32}-\d+) is container id used by AWS ECS, length: 43
// ([0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){4}) is container id used by Garden, length: 28
var ContainerIDPatternStr = "([0-9a-fA-F]{64})|([0-9a-fA-F]{32}-\\d+)|([0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){4})"
var containerIDPattern = regexp.MustCompile(ContainerIDPatternStr)

var containerIDCoreChars = "0123456789abcdefABCDEF"

// FindContainerID extracts the first sub string that matches the pattern of a container ID
func FindContainerID(s string) (string, uint64) {
	match := containerIDPattern.FindIndex([]byte(s))
	if match == nil {
		return "", 0
	}

	// first, check what's before
	if match[0] != 0 {
		previousChar := string(s[match[0]-1])
		if strings.ContainsAny(previousChar, containerIDCoreChars) {
			return "", 0
		}
	}
	// then, check what's after
	if match[1] < len(s) {
		nextChar := string(s[match[1]])
		if strings.ContainsAny(nextChar, containerIDCoreChars) {
			return "", 0
		}
	}

	// ensure the found containerID is delimited by charaters other than a-zA-Z0-9, or that
	// it starts or/and ends the initial string

	cgroupID := s[match[0]:match[1]]
	containerID, flags := model.GetContainerFromCgroup(cgroupID)
	return containerID, flags
}
