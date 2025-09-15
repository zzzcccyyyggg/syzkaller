package main

import (
	"fmt"
	"regexp"
)

func main() {
	// Test the ignore pattern
	pattern := "SYZFATAL:"
	testLine := "2025/09/13 15:57:07 SYZFATAL: executor 0 failed 11 times: bad call 2 index 195948557/2"
	
	re, err := regexp.Compile(pattern)
	if err != nil {
		fmt.Printf("Error compiling regex: %v\n", err)
		return
	}
	
	fmt.Printf("Pattern: %s\n", pattern)
	fmt.Printf("Test line: %s\n", testLine)
	fmt.Printf("Match result: %t\n", re.Match([]byte(testLine)))
	
	// Test with different patterns
	patterns := []string{
		"SYZFATAL:",
		"^SYZFATAL:",
		".*SYZFATAL:.*",
	}
	
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			fmt.Printf("Error with pattern %s: %v\n", p, err)
			continue
		}
		fmt.Printf("Pattern '%s' matches: %t\n", p, re.Match([]byte(testLine)))
	}
}