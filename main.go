package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	sigma "github.com/runreveal/sigmalite"
)

type Match struct {
	Timestamp string         `json:"timestamp"`
	Rule      RuleInfo       `json:"rule"`
	Event     map[string]any `json:"event"`
}

type RuleInfo struct {
	Title       string   `json:"title"`
	ID          string   `json:"id,omitempty"`
	Level       string   `json:"level,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

func main() {
	rulesDir := "./rules"
	if len(os.Args) > 1 {
		rulesDir = os.Args[1]
	}

	rules, err := loadRules(rulesDir)
	if err != nil {
		log.Fatalf("failed to load rules: %v", err)
	}
	if len(rules) == 0 {
		log.Fatalf("no valid rules found in %s", rulesDir)
	}

	log.Printf("loaded %d sigma rule(s) from %s", len(rules), rulesDir)
	for _, r := range rules {
		log.Printf("  [%s] %s", r.Level, r.Title)
	}
	log.Printf("reading eslogger events from stdin...")

	// Increase scanner buffer — eslogger events with large argument lists can
	// exceed the default 64 KB limit.
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 256*1024), 10*1024*1024)

	// Flush stdout immediately on each match so consumers see results in real time.
	stdout := bufio.NewWriter(os.Stdout)
	defer stdout.Flush()
	enc := json.NewEncoder(stdout)

	var eventCount, matchCount int

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var raw map[string]any
		if err := json.Unmarshal(line, &raw); err != nil {
			// eslogger occasionally emits non-JSON status lines; skip silently.
			continue
		}
		eventCount++

		// Flatten nested JSON to dot-notation keys so sigma field references work
		// directly (e.g. "event.exec.target.executable.path").
		// The full JSON line is also stored as Message to support keyword detections.
		entry := &sigma.LogEntry{
			Message: string(line),
			Fields:  flattenJSON(raw),
		}

		for _, rule := range rules {
			if rule.Detection.Matches(entry, nil) {
				matchCount++
				m := Match{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Rule: RuleInfo{
						Title:       rule.Title,
						ID:          rule.ID,
						Level:       string(rule.Level),
						Description: rule.Description,
						Tags:        rule.Tags,
					},
					Event: raw,
				}
				if err := enc.Encode(m); err != nil {
					log.Printf("error encoding match: %v", err)
					continue
				}
				stdout.Flush()
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("stdin read error: %v", err)
	}

	log.Printf("done — processed %d events, %d match(es)", eventCount, matchCount)
}

// loadRules reads all *.yml / *.yaml files from dir, parses them as Sigma rules,
// and returns the valid ones. Parse failures are logged but not fatal.
func loadRules(dir string) ([]*sigma.Rule, error) {
	var files []string
	for _, ext := range []string{"*.yml", "*.yaml"} {
		m, err := filepath.Glob(filepath.Join(dir, ext))
		if err != nil {
			return nil, fmt.Errorf("glob %s: %w", ext, err)
		}
		files = append(files, m...)
	}

	var rules []*sigma.Rule
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Printf("warning: skipping %s: %v", filepath.Base(f), err)
			continue
		}
		rule, err := sigma.ParseRule(data)
		if err != nil {
			log.Printf("warning: skipping %s: %v", filepath.Base(f), err)
			continue
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// flattenJSON converts a nested JSON object into a flat map[string]string using
// dot-notation keys. This maps directly to the field paths used in Sigma rules
// written against eslogger output.
//
// Arrays are stored at both indexed keys (args.0, args.1, ...) and as a single
// space-joined string at the parent key so that |contains modifiers work across
// all array elements without requiring per-index references.
func flattenJSON(data map[string]any) map[string]string {
	out := make(map[string]string, 32)
	flattenVal(data, "", out)
	return out
}

func flattenVal(v any, prefix string, out map[string]string) {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flattenVal(child, key, out)
		}

	case []any:
		// Index each element individually.
		var strs []string
		for i, child := range val {
			flattenVal(child, fmt.Sprintf("%s.%d", prefix, i), out)
			// Collect string values for the composite parent entry.
			if s, ok := child.(string); ok {
				strs = append(strs, s)
			}
		}
		// Also store the whole array as a space-joined string at the parent key
		// so rules can use: args|contains: "suspicious-flag"
		if len(strs) > 0 && prefix != "" {
			out[prefix] = strings.Join(strs, " ")
		}

	case string:
		if prefix != "" {
			out[prefix] = val
		}

	case float64:
		if prefix != "" {
			// Avoid spurious decimal points on integer-valued JSON numbers.
			if val == float64(int64(val)) {
				out[prefix] = fmt.Sprintf("%d", int64(val))
			} else {
				out[prefix] = fmt.Sprintf("%g", val)
			}
		}

	case bool:
		if prefix != "" {
			out[prefix] = fmt.Sprintf("%t", val)
		}

	case nil:
		// skip
	}
}
