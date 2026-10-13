package vendorimport

import (
	"errors"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// mergeVendorYAML adds values to a vendor.yaml by editing lines, so that
// comments, quoting and line breaks of the existing file stay as they are
// (re-encoding with yaml.v3 would reflow folded text).
func mergeVendorYAML(src []byte, a additions) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("not a YAML mapping")
	}
	m := &yamlFile{root: doc.Content[0], lines: strings.Split(string(src), "\n")}
	for _, l := range []struct {
		key     string
		values  []string
		comment string
	}{
		{"manufacturer_ids", a.ManufacturerIDs, ""},
		{"chain_nv_indices", a.ChainNVIndices, "# NV indices holding chain certificates as concatenated DER."},
		{"domains", a.Domains, "# Hosts the vendor publishes certificates on (tpm2-ek vendor import)."},
	} {
		if err := m.addToList(l.key, l.values, l.comment); err != nil {
			return nil, err
		}
	}
	if err := m.addCertificates(a.Certificates); err != nil {
		return nil, err
	}
	return []byte(m.result()), nil
}

type yamlFile struct {
	root  *yaml.Node
	lines []string
	edits []edit
}

// edit replaces lines[at:at+del] by ins.
type edit struct {
	at, del int
	ins     []string
}

func (m *yamlFile) result() string {
	sort.SliceStable(m.edits, func(i, j int) bool { return m.edits[i].at > m.edits[j].at })
	lines := slices.Clone(m.lines)
	for _, e := range m.edits {
		lines = slices.Replace(lines, e.at, e.at+e.del, e.ins...)
	}
	return strings.Join(lines, "\n")
}

// key returns the index of a top level key in root.Content, or -1.
func (m *yamlFile) key(name string) int {
	for i := 0; i+1 < len(m.root.Content); i += 2 {
		if m.root.Content[i].Value == name {
			return i
		}
	}
	return -1
}

// blockEnd returns the line index after the value of the key at content
// index i, excluding blank and comment lines that precede the next key.
func (m *yamlFile) blockEnd(i int) int {
	end := len(m.lines)
	if i+2 < len(m.root.Content) {
		end = m.root.Content[i+2].Line - 1
	}
	start := m.root.Content[i].Line
	for end > start {
		t := strings.TrimSpace(m.lines[end-1])
		if t != "" && !strings.HasPrefix(t, "#") {
			break
		}
		end--
	}
	return end
}

// insertBefore returns the line index to insert a new top level key at:
// before "certificates" (and its comments) or at the end.
func (m *yamlFile) insertBefore() int {
	i := m.key("certificates")
	if i < 0 {
		end := len(m.lines)
		for end > 0 && strings.TrimSpace(m.lines[end-1]) == "" {
			end--
		}
		return end
	}
	at := m.root.Content[i].Line - 1
	for at > 0 && strings.HasPrefix(strings.TrimSpace(m.lines[at-1]), "#") {
		at--
	}
	return at
}

func (m *yamlFile) addToList(key string, values []string, comment string) error {
	i := m.key(key)
	if i < 0 {
		if len(values) == 0 {
			return nil
		}
		var ins []string
		if comment != "" {
			ins = append(ins, comment)
		}
		ins = append(ins, key+": ["+strings.Join(values, ", ")+"]")
		m.edits = append(m.edits, edit{at: m.insertBefore(), ins: ins})
		return nil
	}
	k, v := m.root.Content[i], m.root.Content[i+1]
	if v.Kind != yaml.SequenceNode {
		return errors.New(key + " is not a list")
	}
	var add []string
	for _, x := range values {
		if !slices.ContainsFunc(v.Content, func(n *yaml.Node) bool { return strings.EqualFold(n.Value, x) }) {
			add = append(add, x)
		}
	}
	if len(add) == 0 {
		return nil
	}
	if v.Style&yaml.FlowStyle != 0 || len(v.Content) == 0 {
		if v.Line != k.Line || m.blockEnd(i) != k.Line {
			return errors.New(key + ": multi-line flow lists are not supported")
		}
		var items []string
		for _, n := range v.Content {
			items = append(items, flowItem(n))
		}
		line := key + ": [" + strings.Join(append(items, add...), ", ") + "]"
		if c := v.LineComment + k.LineComment; c != "" {
			line += " " + c
		}
		m.edits = append(m.edits, edit{at: k.Line - 1, del: 1, ins: []string{line}})
		return nil
	}
	pad := strings.Repeat(" ", max(v.Content[0].Column-3, 0))
	var ins []string
	for _, x := range add {
		ins = append(ins, pad+"- "+x)
	}
	m.edits = append(m.edits, edit{at: m.blockEnd(i), ins: ins})
	return nil
}

// flowItem renders an existing list item as it was written.
func flowItem(n *yaml.Node) string {
	switch n.Style {
	case yaml.DoubleQuotedStyle:
		return quote(n.Value)
	case yaml.SingleQuotedStyle:
		return "'" + strings.ReplaceAll(n.Value, "'", "''") + "'"
	}
	return n.Value
}

func (m *yamlFile) addCertificates(items []string) error {
	if len(items) == 0 {
		return nil
	}
	i := m.key("certificates")
	if i < 0 {
		ins := []string{"certificates:"}
		for _, it := range items {
			ins = append(ins, strings.Split(indent(it, "  "), "\n")...)
		}
		m.edits = append(m.edits, edit{at: m.insertBefore(), ins: ins})
		return nil
	}
	k, v := m.root.Content[i], m.root.Content[i+1]
	if v.Kind != yaml.SequenceNode {
		return errors.New("certificates is not a list")
	}
	if len(v.Content) == 0 {
		if m.blockEnd(i) != k.Line {
			return errors.New("certificates: unexpected layout")
		}
		ins := []string{"certificates:"}
		for _, it := range items {
			ins = append(ins, strings.Split(indent(it, "  "), "\n")...)
		}
		m.edits = append(m.edits, edit{at: k.Line - 1, del: 1, ins: ins})
		return nil
	}
	if v.Style&yaml.FlowStyle != 0 {
		return errors.New("certificates: flow style lists are not supported")
	}
	pad := strings.Repeat(" ", max(v.Content[0].Column-3, 0))
	var ins []string
	for _, it := range items {
		ins = append(ins, strings.Split(indent(it, pad), "\n")...)
	}
	m.edits = append(m.edits, edit{at: m.blockEnd(i), ins: ins})
	return nil
}
