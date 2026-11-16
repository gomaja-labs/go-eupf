package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestConfigurationReferenceCoversStartupSettings(t *testing.T) {
	doc, err := os.ReadFile("../../docs/Configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	source, err := parser.ParseFile(token.NewFileSet(), "config.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	flags := make(map[string]string)
	ast.Inspect(source, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "BindPFlag" {
			return true
		}
		key, ok := call.Args[0].(*ast.BasicLit)
		lookup, lookupOK := call.Args[1].(*ast.CallExpr)
		if !ok || !lookupOK || len(lookup.Args) != 1 {
			return true
		}
		flag, ok := lookup.Args[0].(*ast.BasicLit)
		if ok {
			keyText, keyErr := strconv.Unquote(key.Value)
			flagText, flagErr := strconv.Unquote(flag.Value)
			if keyErr != nil || flagErr != nil {
				t.Fatal("nonliteral configuration binding")
			}
			flags[keyText] = flagText
		}
		return true
	})

	rows := make(map[string][]string)
	for line := range strings.SplitSeq(string(doc), "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 8 {
			continue
		}
		for i := range cells {
			cells[i] = strings.Trim(strings.TrimSpace(cells[i]), "`")
		}
		if _, exists := rows[cells[0]]; exists {
			t.Errorf("duplicate setting %s", cells[0])
		}
		rows[cells[0]] = cells
	}
	for field := range reflect.TypeFor[UpfConfig]().Fields() {
		key := field.Tag.Get("mapstructure")
		if key == "" {
			continue
		}
		row, ok := rows[key]
		if !ok {
			t.Errorf("undocumented startup setting %s", key)
			continue
		}
		if row[1] != "UPF_"+strings.ToUpper(key) || row[2] != "--"+flags[key] {
			t.Errorf("%s: environment or flag differs from binding: %v", key, row[:3])
		}
		for _, cell := range row[3:] {
			if cell == "" {
				t.Errorf("%s: missing default, range, application, Helm name or purpose", key)
			}
		}
		delete(rows, key)
	}
	for key := range rows {
		t.Errorf("documented setting %s does not exist", key)
	}
}
