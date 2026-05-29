package exposure

import "strings"

// BackupExtensions returns the suffix list used to permute backup-file
// candidates for any crawled path. Mirrors the systematic permutation AWVS
// performs in `Backup_File.script` / `Backup_Folder.script` — applied per
// discovered file rather than as a static wordlist.
func BackupExtensions() []string {
	return []string{
		".bak",
		".old",
		".orig",
		".save",
		".swp",
		".swo",
		".tmp",
		".backup",
		".copy",
		".inc",
		".0",
		".1",
		".2",
		"~",
		"_old",
		"_bak",
		"_backup",
	}
}

// editorPrefixSwaps returns extensions whose conventional backup form
// prefixes the basename with a dot rather than appending a suffix
// (vim's swap files: `.config.php.swp`, joe's variants, emacs `.#file`).
func editorPrefixSwaps() []string {
	return []string{".swp", ".swo", ".swn"}
}

// GenerateBackupVariants returns the set of likely backup-filename
// permutations for a discovered path, preserving any directory prefix.
//
// For `index.php` it emits `index.php.bak`, `index.php.old`, `index.php~`,
// `.index.php.swp`, etc. For `admin/config.php` the swap-style variant
// becomes `admin/.config.php.swp` (dot on the basename, not the path).
//
// The input path itself is never included in the result, and duplicates
// are removed.
func GenerateBackupVariants(path string) []string {
	if path == "" {
		return nil
	}

	dir, base := splitDirBase(path)
	swapSet := make(map[string]bool, len(editorPrefixSwaps()))
	for _, e := range editorPrefixSwaps() {
		swapSet[e] = true
	}

	seen := make(map[string]bool, 32)
	var out []string

	add := func(s string) {
		if s == "" || s == path || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	for _, ext := range BackupExtensions() {
		if swapSet[ext] {
			// vim-style: dot-prefix on basename, suffix on basename.
			add(dir + "." + base + ext)
			// Also the trailing-suffix form (some servers expose either).
			add(dir + base + ext)
			continue
		}
		add(dir + base + ext)
	}

	// Emacs auto-save: `#file#` and lock `.#file`.
	add(dir + "#" + base + "#")
	add(dir + ".#" + base)

	return out
}

// splitDirBase splits `a/b/c.php` into (`a/b/`, `c.php`). For a basename
// with no directory it returns ("", path).
func splitDirBase(path string) (string, string) {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return "", path
	}
	return path[:i+1], path[i+1:]
}
