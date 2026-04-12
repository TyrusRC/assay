// Package pathnorm provides Path Normalization Bypass vulnerability detection.
// It uses multiple techniques to bypass access controls including:
//   - Semicolon path traversal (Spring/Tomcat bypass)
//   - Double dot path traversal
//   - URL-encoded and double URL-encoded traversal
//   - Dot segment manipulation
package pathnorm
