package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/deepfence/YaraHunter/pkg/threatintel"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: convert-rules <input.json> <output.yar>")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	outputFile := os.Args[2]

	data, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	var fb threatintel.FeedsBundle
	if err := json.Unmarshal(data, &fb); err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	if err := threatintel.ExportYaraRules(outputFile, fb.ScannerFeeds.SecretRules, fb.Extra); err != nil {
		fmt.Printf("Error exporting rules: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully converted %d rules to %s\n", len(fb.ScannerFeeds.SecretRules), outputFile)
}
