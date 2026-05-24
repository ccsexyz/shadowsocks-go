package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/urfave/cli/v2"
)

//go:embed compare.html
var compareHTML string

var compareCommand = &cli.Command{
	Name:      "compare",
	Usage:     "compare benchmark results and generate HTML report",
	ArgsUsage: "[--label L1] <file1.json> [--label L2] <file2.json> ...",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{Name: "label", Usage: "label for the preceding file"},
		&cli.BoolFlag{Name: "html", Usage: "generate HTML report"},
		&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "output file (- for stdout)"},
	},
	Action: func(c *cli.Context) error {
		labels := c.StringSlice("label")
		files := c.Args().Slice()
		if len(files) == 0 {
			return fmt.Errorf("at least one results file required")
		}

		type named struct{ label, file string }
		var entries []named
		for i, f := range files {
			l := fmt.Sprintf("V%d", i+1)
			if i < len(labels) {
				l = labels[i]
			}
			entries = append(entries, named{l, f})
		}

		var allResults [][]result
		var allLabels []string
		for _, e := range entries {
			data, err := os.ReadFile(e.file)
			if err != nil {
				return fmt.Errorf("read %s: %w", e.file, err)
			}
			var res []result
			if err := json.Unmarshal(data, &res); err != nil {
				return fmt.Errorf("parse %s: %w", e.file, err)
			}
			allResults = append(allResults, res)
			allLabels = append(allLabels, e.label)
		}

		if c.Bool("html") {
			return renderHTML(allResults, allLabels, c.String("output"))
		}
		printTextCompare(allResults, allLabels)
		return nil
	},
}

func printTextCompare(allResults [][]result, labels []string) {
	// Collect all unique method/mode/payload combos
	type key struct {
		method, mode string
		payload      int
	}
	keys := make(map[key]bool)
	for _, res := range allResults {
		for _, r := range res {
			if r.Error != "" {
				continue
			}
			keys[key{r.Method, r.Mode, r.Payload}] = true
		}
	}

	fmt.Printf("%-28s %-6s %6s ", "method", "mode", "payl")
	for i, l := range labels {
		_ = i
		fmt.Printf("%12s ", l)
	}
	fmt.Println()
	fmt.Println(strings.Repeat("-", 28+6+6+13*len(labels)))

	for k := range keys {
		fmt.Printf("%-28s %-6s %6d ", k.method, k.mode, k.payload)
		for _, res := range allResults {
			avg := 0.0
			n := 0
			for _, r := range res {
				if r.Method == k.method && r.Mode == k.mode && r.Payload == k.payload && r.Error == "" {
					avg += r.Throughput
					n++
				}
			}
			if n > 0 {
				avg /= float64(n)
				fmt.Printf("%10.1f MB ", avg)
			} else {
				fmt.Printf("%12s ", "N/A")
			}
		}
		fmt.Println()
	}
}

type tmplData struct {
	Labels     []string
	Results    [][]result
	RowsJSON   string
	LabelsJSON string
	MaxTput    float64
	PprofJSON  string
	PprofSVGs  string
}

type rowResult struct {
	Method      string      `json:"method"`
	Payload     int         `json:"payload"`
	Concurrency int         `json:"concurrency"`
	Values      [][]float64 `json:"values"`
}

func buildPprofData(allResults [][]result, labels []string) (string, string) {
	type pprofVer struct {
		Label  string      `json:"label"`
		Allocs []pprofSite `json:"allocs"`
	}
	type pprofSVG struct {
		Label      string `json:"label"`
		CPUPath    string `json:"cpu_path"`
		CPUSVG     string `json:"cpu_svg"`
		AllocsPath string `json:"allocs_path"`
		AllocsSVG  string `json:"allocs_svg"`
		HeapPath   string `json:"heap_path"`
		HeapSVG    string `json:"heap_svg"`
		CPURaw     string `json:"cpu_raw"`
		AllocsRaw  string `json:"allocs_raw"`
		HeapRaw    string `json:"heap_raw"`
	}
	var vers []pprofVer
	var svgs []pprofSVG
	for vi, allRes := range allResults {
		label := labels[vi]
		var sites []pprofSite
		var svg pprofSVG
		svg.Label = label
		for _, r := range allRes {
			if r.Error != "" {
				continue
			}
			if r.PprofAllocs != nil {
				sites = r.PprofAllocs
			}
			if r.PprofCPUSVG != "" {
				if data, err := os.ReadFile(r.PprofCPUSVG); err == nil {
					svg.CPURaw = string(data)
					svg.CPURaw = string(data)
					svg.CPUSVG = stripSVGContent(string(data))
				}
			}
			if r.PprofAllocsSVG != "" {
				if data, err := os.ReadFile(r.PprofAllocsSVG); err == nil {
					svg.AllocsRaw = string(data)
					svg.AllocsRaw = string(data)
					svg.AllocsSVG = stripSVGContent(string(data))
				}
			}
			if r.PprofHeapSVG != "" {
				if data, err := os.ReadFile(r.PprofHeapSVG); err == nil {
					svg.HeapRaw = string(data)
					svg.HeapRaw = string(data)
					svg.HeapSVG = stripSVGContent(string(data))
				}
			}
			if sites != nil && svg.CPUSVG != "" {
				break
			}
		}
		// Read raw SVGs (with SVGPan) from separate files
		for _, r := range allRes {
			if r.PprofCPUSVGRaw != "" {
				if data, err := os.ReadFile(r.PprofCPUSVGRaw); err == nil {
					if i := strings.Index(string(data), "<svg"); i >= 0 {
						svg.CPURaw = string(data)[i:]
					}
				}
			}
			if r.PprofAllocsSVGRaw != "" {
				if data, err := os.ReadFile(r.PprofAllocsSVGRaw); err == nil {
					if i := strings.Index(string(data), "<svg"); i >= 0 {
						svg.AllocsRaw = string(data)[i:]
					}
				}
			}
			if r.PprofHeapSVGRaw != "" {
				if data, err := os.ReadFile(r.PprofHeapSVGRaw); err == nil {
					if i := strings.Index(string(data), "<svg"); i >= 0 {
						svg.HeapRaw = string(data)[i:]
					}
				}
			}
			if svg.CPURaw != "" {
				break
			}
		}
		if sites == nil {
			sites = []pprofSite{}
		}
		vers = append(vers, pprofVer{Label: label, Allocs: sites})
		svgs = append(svgs, svg)
	}
	b1, _ := json.Marshal(vers)
	b2, _ := json.Marshal(svgs)
	return string(b1), string(b2)
}

// removeScriptTags removes <script>...</script> blocks from SVG for safe innerHTML embedding.
func removeScriptTags(s string) string {
	for {
		i := strings.Index(s, "<script")
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], "</script>")
		if j < 0 {
			s = s[:i]
			break
		}
		s = s[:i] + s[i+j+len("</script>"):]
	}
	return s
}

var svgAttrRe = regexp.MustCompile(`(?i)\s(width|height)=["'][^"']*["']`)

func stripSVGContent(data string) string {
	if i := strings.Index(data, "<svg"); i >= 0 {
		data = data[i:]
	}
	// Remove width/height attrs so CSS 100%/auto can control sizing
	data = svgAttrRe.ReplaceAllString(data, "")
	data = removeScriptTags(data)
	return data
}

func renderHTML(allResults [][]result, labels []string, output string) error {
	tmpl, err := template.New("compare").Parse(compareHTML)
	if err != nil {
		return err
	}

	// Sort results within each version
	for i := range allResults {
		sort.Slice(allResults[i], func(a, b int) bool {
			if allResults[i][a].Method != allResults[i][b].Method {
				return allResults[i][a].Method < allResults[i][b].Method
			}
			if allResults[i][a].Payload != allResults[i][b].Payload {
				return allResults[i][a].Payload < allResults[i][b].Payload
			}
			return allResults[i][a].Concurrency < allResults[i][b].Concurrency
		})
	}

	// Build flat ROWS: one entry per unique (method, payload, concurrency) combo
	type key struct {
		method, mode  string
		payload, conc int
	}
	rowMap := make(map[key]*rowResult)
	var rowOrder []key
	for vi, res := range allResults {
		for _, r := range res {
			k := key{r.Method, r.Mode, r.Payload, r.Concurrency}
			if _, ok := rowMap[k]; !ok {
				rowMap[k] = &rowResult{
					Method:      r.Method,
					Payload:     r.Payload,
					Concurrency: r.Concurrency,
					Values:      make([][]float64, len(allResults)),
				}
				rowOrder = append(rowOrder, k)
			}
			rowMap[k].Values[vi] = []float64{
				// 0:throughput 1:cpu 2:gc_time_ms 3:rtt_p50 4:max_heap 5:gc_cycles 6:alloc_mb
				r.Throughput, r.CPU, r.GCClock, r.RttP50,
				r.MaxHeap, float64(r.GCCycles), r.AllocMB,
				r.AvgHeap, r.FbP50, r.FbP95, r.FbP99, r.RttP95, r.RttP99,
			}
		}
	}
	var rows []rowResult
	for _, k := range rowOrder {
		rows = append(rows, *rowMap[k])
	}

	maxTput := 0.0
	for _, row := range rows {
		for _, v := range row.Values {
			if v != nil && v[0] > maxTput {
				maxTput = v[0]
			}
		}
	}

	rowsJSON, _ := json.Marshal(rows)
	labelsJSON, _ := json.Marshal(labels)

	pprofJSON, pprofSVGs := buildPprofData(allResults, labels)

	var buf strings.Builder
	if err := tmpl.Execute(&buf, tmplData{
		Labels: labels, Results: allResults,
		RowsJSON: string(rowsJSON), LabelsJSON: string(labelsJSON),
		MaxTput: maxTput, PprofJSON: pprofJSON, PprofSVGs: pprofSVGs,
	}); err != nil {
		return fmt.Errorf("render template: %w", err)
	}

	if output == "" || output == "-" {
		fmt.Print(buf.String())
	} else {
		os.WriteFile(output, []byte(buf.String()), 0644)
	}
	return nil
}
