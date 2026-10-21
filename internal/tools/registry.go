package tools

// Registry holds discovered external tools and maps vulnerability classes
// to the best available tool for each class.
type Registry struct {
	tools []Tool
}

// NewRegistry creates a registry and discovers all available tools.
// Callers supply the concrete tool instances so the tools package
// stays free of cyclic imports into sub-packages.
func NewRegistry(all []Tool) *Registry {
	return &Registry{tools: all}
}

// Available returns tools that passed the IsAvailable check.
func (r *Registry) Available() []Tool {
	var out []Tool
	for _, t := range r.tools {
		if t.IsAvailable() {
			out = append(out, t)
		}
	}
	return out
}

// All returns every registered tool regardless of availability.
func (r *Registry) All() []Tool {
	return r.tools
}

// ByName returns the tool with the given name or nil.
func (r *Registry) ByName(name string) Tool {
	for _, t := range r.tools {
		if t.Name() == name {
			return t
		}
	}
	return nil
}

// classTools maps a vulnerability class name to the tool names that
// test it best. First entry is preferred; the rest are fallbacks.
var classTools = map[string][]string{
	"sqli":  {"sqlmap", "ghauri"},
	"xss":   {"dalfox"},
	"cmdi":  {"commix"},
	"ssti":  {"tplmap"},
	"misc":  {"nikto"},
	"wp":    {"wpscan"},
	"nuclei": {"nuclei"},
}

// ForClass returns the available tools for a vulnerability class,
// in preference order.
func (r *Registry) ForClass(vulnClass string) []Tool {
	names, ok := classTools[vulnClass]
	if !ok {
		return nil
	}
	var out []Tool
	for _, name := range names {
		if t := r.ByName(name); t != nil && t.IsAvailable() {
			out = append(out, t)
		}
	}
	return out
}
