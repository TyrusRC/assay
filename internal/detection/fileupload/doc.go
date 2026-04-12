// Package fileupload provides File Upload vulnerability detection.
// It uses multiple detection techniques including:
//   - Dangerous extension upload testing (.php, .jsp, .asp, .aspx, .exe, .sh, .py)
//   - MIME type bypass detection (sending executables with image content types)
//   - Double extension bypass (.php.jpg, .php.png)
//   - Null byte injection in filenames (file.php%00.jpg)
package fileupload
