package iast

import "embed"

//go:embed sensors/sensor.php
var SensorPHP string

//go:embed sensors/sensor.js
var SensorJS string

//go:embed sensors/sensor.py
var SensorPython string

//go:embed sensors/sensor.php sensors/sensor.js sensors/sensor.py
var SensorFS embed.FS

// SensorLanguages maps language aliases to sensor file names.
var SensorLanguages = map[string]string{
	"php":    "sensor.php",
	"node":   "sensor.js",
	"nodejs": "sensor.js",
	"js":     "sensor.js",
	"python": "sensor.py",
	"py":     "sensor.py",
}

// SensorContent returns the sensor source for a given language key.
func SensorContent(lang string) (string, bool) {
	switch lang {
	case "php":
		return SensorPHP, true
	case "node", "nodejs", "js":
		return SensorJS, true
	case "python", "py":
		return SensorPython, true
	default:
		return "", false
	}
}
