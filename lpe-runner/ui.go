package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// version of the toolkit.
const version = "2.0"

// ANSI color helpers (disabled when stdout is not a TTY).
var (
	colR, colG, colY, colC, colB, colM, colW, colD, colZ string
)

func initColors() {
	if !isTTY(os.Stdout) {
		colR, colG, colY, colC, colB, colM, colW, colD, colZ = "", "", "", "", "", "", "", "", ""
		return
	}
	colR = "\033[1;31m"
	colG = "\033[1;32m"
	colY = "\033[1;33m"
	colC = "\033[1;36m"
	colB = "\033[1;34m"
	colM = "\033[1;35m"
	colW = "\033[1;37m"
	colD = "\033[2;37m"
	colZ = "\033[0m"
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// banner prints the toolkit header.
func banner() {
	fmt.Print(colW)
	fmt.Println("==============================================================================")
	fmt.Printf("  PabloRoot v%s\n", version)
	fmt.Println("  Telegram: https://t.me/symlink")
	fmt.Println("==============================================================================")
	fmt.Print(colZ)
	fmt.Println()
}

func logf(level, msg string, args ...any) {
	var tag, c string
	switch level {
	case "ok":
		tag, c = "[+]", colG
	case "bad":
		tag, c = "[-]", colR
	case "warn":
		tag, c = "[!]", colY
	case "info":
		tag, c = "[*]", colC
	case "step":
		tag, c = "[>]", colB
	case "head":
		tag, c = "[#]", colM
	default:
		tag, c = "[?]", colW
	}
	fmt.Printf("%s%s%s %s\n", c, tag, colZ, fmt.Sprintf(msg, args...))
	// Flush immediately so progress shows up in real time even when
	// stdout is a pipe (e.g. `curl | sh`), where Go otherwise line-buffers.
	os.Stdout.Sync()
}

func okf(f string, a ...any)   { logf("ok", f, a...) }
func badf(f string, a ...any)  { logf("bad", f, a...) }
func warnf(f string, a ...any) { logf("warn", f, a...) }
func infof(f string, a ...any)  { logf("info", f, a...) }
func stepf(f string, a ...any)  { logf("step", f, a...) }
func headf(f string, a ...any)  { logf("head", f, a...) }

func die(f string, a ...any) {
	badf(f, a...)
	os.Exit(1)
}

// atoiSafe parses an int, returning 0 on error.
func atoiSafe(s string) int {
	v, _ := strconv.Atoi(strings.TrimSpace(s))
	return v
}
