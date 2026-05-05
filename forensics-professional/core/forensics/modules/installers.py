"""Submodule installers.

Each installer is a small callable that performs one logical install
step and may shell out via :class:`CommandRunner`. Installers are
mapped to ``(module, submodule)`` keys via :data:`INSTALLERS`.

Every installer is expected to be idempotent: calling it twice does no
harm. Verification is *not* the installer's job — that is handled by
:mod:`forensics.modules.verifier` after the installer returns.
"""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Callable, Iterator

from forensics.config import get_config

log = logging.getLogger("forensics.modules.installers")

# A SubmoduleInstaller is a callable that takes (CommandRunner) and returns None.
SubmoduleInstaller = Callable[["CommandRunner"], None]


class CommandRunner:
    """Subprocess runner with streaming output and structured logging.

    Each command writes both to stdout (so the analyst sees progress) and
    to a per-installation log file under ``/var/log/forensics/installations/``.
    """

    def __init__(self, log_path: Path, *, stream: bool = True, timeout: int = 900):
        self.log_path = log_path
        self.stream = stream
        self.timeout = timeout
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    # Used by installers ------------------------------------------------------

    def run(self, cmd: list[str] | str, *, ignore_failure: bool = False) -> int:
        """Run *cmd*. Streams output. Returns the exit code."""
        if isinstance(cmd, str):
            cmd_str = cmd
            shell = True
        else:
            cmd_str = " ".join(shlex.quote(c) for c in cmd)
            shell = False

        self._log(f"$ {cmd_str}")
        try:
            return self._run_streaming(cmd, shell=shell, ignore_failure=ignore_failure)
        except subprocess.TimeoutExpired:
            self._log(f"TIMEOUT after {self.timeout}s: {cmd_str}")
            if not ignore_failure:
                raise RuntimeError(f"timeout: {cmd_str}")
            return 124

    def apt_install(self, *packages: str) -> None:
        if not packages:
            return
        self.run(["sudo", "DEBIAN_FRONTEND=noninteractive",
                  "apt-get", "install", "-y", *packages],
                 ignore_failure=False)

    def apt_update(self) -> None:
        self.run(["sudo", "apt-get", "update"], ignore_failure=True)

    def pip_install(self, *packages: str) -> None:
        if not packages:
            return
        cmd = ["sudo", "pip3", "install", "--break-system-packages",
               "--no-cache-dir", *packages]
        self.run(cmd, ignore_failure=False)

    def shell(self, cmdline: str, *, ignore_failure: bool = False) -> None:
        """Run a one-shot bash command. Avoid where possible."""
        self.run(["bash", "-c", cmdline], ignore_failure=ignore_failure)

    # Internals ---------------------------------------------------------------

    def _log(self, text: str) -> None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = f"[{ts}] {text}\n"
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
        if self.stream:
            print(line.rstrip())

    def _run_streaming(self, cmd, *, shell: bool, ignore_failure: bool) -> int:
        proc = subprocess.Popen(
            cmd,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None

        deadline = time.monotonic() + self.timeout
        try:
            for raw in proc.stdout:
                self._log(raw.rstrip())
                if time.monotonic() > deadline:
                    proc.terminate()
                    raise subprocess.TimeoutExpired(cmd=cmd, timeout=self.timeout)
        finally:
            try:
                rc = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                rc = proc.wait()

        if rc != 0 and not ignore_failure:
            raise RuntimeError(f"command exited {rc}: {cmd}")
        return rc


# ============================================================================
# INSTALLERS — one function per submodule
# ============================================================================
# These functions intentionally do NOT verify success themselves; that
# happens in verifier.py based on the registry's `verify` hints.

# ── cloud-forensics ──────────────────────────────────────────────────────────
def cloud_aws(r: CommandRunner) -> None:
    r.apt_update()
    r.apt_install("curl", "unzip")
    r.shell(
        "curl -fsSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip "
        "-o /tmp/awscliv2.zip && "
        "unzip -qo /tmp/awscliv2.zip -d /tmp && "
        "sudo /tmp/aws/install --update && "
        "rm -rf /tmp/aws /tmp/awscliv2.zip",
    )
    r.pip_install("boto3", "s3transfer")


def cloud_azure(r: CommandRunner) -> None:
    r.shell("curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash")
    r.pip_install("azure-mgmt-compute", "azure-mgmt-storage", "azure-identity")


def cloud_gcp(r: CommandRunner) -> None:
    r.shell(
        'echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] '
        'https://packages.cloud.google.com/apt cloud-sdk main" | '
        'sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list',
    )
    r.shell(
        "curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | "
        "sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg",
    )
    r.apt_update()
    r.apt_install("google-cloud-cli")


def cloud_generic(r: CommandRunner) -> None:
    r.pip_install("scoutsuite", "prowler")


# ── memory-forensics ─────────────────────────────────────────────────────────
def memory_volatility(r: CommandRunner) -> None:
    r.pip_install("volatility3")


def memory_lime(r: CommandRunner) -> None:
    r.apt_install("git", "build-essential")
    r.shell(
        "git clone --depth 1 https://github.com/504ensicsLabs/LiME /tmp/LiME && "
        "cd /tmp/LiME/src && make 2>&1 | tail -20 || true",
        ignore_failure=True,
    )


def memory_avml(r: CommandRunner) -> None:
    # Microsoft AVML — pre-built linux binary from latest release.
    r.shell(
        "URL=$(curl -fsSL https://api.github.com/repos/microsoft/avml/releases/latest "
        "  | python3 -c \"import sys,json; "
        "    d=json.load(sys.stdin); "
        "    print(next((a['browser_download_url'] for a in d['assets'] "
        "                 if a['name'].endswith('avml')), ''))\") && "
        "[ -n \"$URL\" ] && "
        "  curl -fsSL \"$URL\" -o /tmp/avml && "
        "  sudo install -o root -g root -m 0755 /tmp/avml /usr/local/bin/avml && "
        "  rm -f /tmp/avml",
    )


# ── disk-forensics ───────────────────────────────────────────────────────────
def disk_sleuthkit(r: CommandRunner) -> None:
    r.apt_install("sleuthkit", "dcfldd", "gddrescue")


def disk_testdisk(r: CommandRunner) -> None:
    r.apt_install("testdisk")


def disk_foremost(r: CommandRunner) -> None:
    r.apt_install("foremost")


def disk_scalpel(r: CommandRunner) -> None:
    r.apt_install("scalpel")


# ── network-forensics ────────────────────────────────────────────────────────
def network_wireshark(r: CommandRunner) -> None:
    r.shell(
        "echo 'wireshark-common wireshark-common/install-setuid boolean false' "
        "| sudo debconf-set-selections",
    )
    r.apt_install("tshark", "wireshark-common")


def network_zeek(r: CommandRunner) -> None:
    r.shell(
        "echo 'deb http://download.opensuse.org/repositories/security:/zeek/"
        "xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/zeek.list",
    )
    r.shell(
        "curl -fsSL https://download.opensuse.org/repositories/security:/zeek/"
        "xUbuntu_22.04/Release.key | sudo gpg --dearmor "
        "-o /etc/apt/trusted.gpg.d/zeek.gpg",
    )
    r.apt_update()
    r.apt_install("zeek")


def network_tcpdump(r: CommandRunner) -> None:
    r.apt_install("tcpdump")


def network_ngrep(r: CommandRunner) -> None:
    r.apt_install("ngrep", "tcpflow")


# ── mobile-forensics ─────────────────────────────────────────────────────────
def mobile_android(r: CommandRunner) -> None:
    r.apt_install("android-tools-adb", "android-tools-fastboot")
    r.pip_install("androguard")


def mobile_ios(r: CommandRunner) -> None:
    r.apt_install("libimobiledevice-utils", "ideviceinstaller", "ifuse")


def mobile_backup_extractors(r: CommandRunner) -> None:
    """Android Backup Extractor — built from source via Gradle."""
    r.apt_install("default-jdk", "git", "sqlite3")
    r.shell(
        "rm -rf /tmp/abe && "
        "git clone --depth 1 https://github.com/nelenkov/android-backup-extractor /tmp/abe && "
        "cd /tmp/abe && ./gradlew --no-daemon && "
        "sudo mkdir -p /opt/forensics/tools && "
        "sudo cp build/libs/abe-all.jar /opt/forensics/tools/abe.jar && "
        "rm -rf /tmp/abe",
    )


# ── malware-analysis ─────────────────────────────────────────────────────────
def malware_yara(r: CommandRunner) -> None:
    r.apt_install("yara")
    r.pip_install("yara-python")


def malware_radare2(r: CommandRunner) -> None:
    # Ubuntu's radare2 is too old; install upstream.
    r.shell(
        "rm -rf /tmp/radare2 && "
        "git clone --depth 1 https://github.com/radareorg/radare2 /tmp/radare2 && "
        "cd /tmp/radare2 && sys/install.sh && rm -rf /tmp/radare2",
    )


def malware_ghidra(r: CommandRunner) -> None:
    r.apt_install("default-jre-headless")
    r.shell(
        "URL=$(curl -fsSL https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest "
        "  | python3 -c \"import sys,json; "
        "    d=json.load(sys.stdin); "
        "    print(next((a['browser_download_url'] for a in d['assets'] "
        "                 if a['name'].endswith('.zip')), ''))\") && "
        "[ -n \"$URL\" ] && "
        "  curl -fsSL \"$URL\" -o /tmp/ghidra.zip && "
        "  sudo mkdir -p /opt/forensics/tools && "
        "  sudo unzip -qo /tmp/ghidra.zip -d /opt/forensics/tools/ && "
        "  rm -f /tmp/ghidra.zip",
    )


def malware_clamav(r: CommandRunner) -> None:
    r.apt_install("clamav")
    r.run(["sudo", "freshclam"], ignore_failure=True)


# ── windows-forensics ────────────────────────────────────────────────────────
def windows_regripper(r: CommandRunner) -> None:
    r.apt_install("libparse-win32registry-perl")
    r.shell(
        "sudo mkdir -p /opt/forensics/tools && "
        "[ -d /opt/forensics/tools/regripper ] || "
        "  sudo git clone --depth 1 https://github.com/keydet89/RegRipper3.0 "
        "  /opt/forensics/tools/regripper",
    )


def windows_plaso(r: CommandRunner) -> None:
    r.run(["sudo", "add-apt-repository", "-y", "ppa:gift/stable"])
    r.apt_update()
    r.apt_install("plaso-tools")


def windows_evtx(r: CommandRunner) -> None:
    r.pip_install("python-evtx")


def windows_prefetch(r: CommandRunner) -> None:
    r.pip_install("prefetch")


# ── linux-forensics ──────────────────────────────────────────────────────────
def linux_auditd(r: CommandRunner) -> None:
    r.apt_install("auditd", "audispd-plugins")


def linux_log_parsers(r: CommandRunner) -> None:
    r.apt_install("logwatch", "goaccess")


def linux_ext4(r: CommandRunner) -> None:
    r.apt_install("e2fsprogs", "extundelete")


# ── container-forensics ──────────────────────────────────────────────────────
def container_docker(r: CommandRunner) -> None:
    r.shell(
        "URL=$(curl -fsSL https://api.github.com/repos/wagoodman/dive/releases/latest "
        "  | python3 -c \"import sys,json; "
        "    d=json.load(sys.stdin); "
        "    print(next((a['browser_download_url'] for a in d['assets'] "
        "                 if 'linux_amd64' in a['name'] and a['name'].endswith('.tar.gz')), ''))\") && "
        "[ -n \"$URL\" ] && "
        "  curl -fsSL \"$URL\" -o /tmp/dive.tar.gz && "
        "  sudo tar -xzf /tmp/dive.tar.gz -C /usr/local/bin dive && "
        "  rm -f /tmp/dive.tar.gz",
    )


def container_kubernetes(r: CommandRunner) -> None:
    r.shell(
        "VER=$(curl -fsSL https://dl.k8s.io/release/stable.txt) && "
        "curl -fsSL https://dl.k8s.io/release/${VER}/bin/linux/amd64/kubectl "
        "  -o /tmp/kubectl && "
        "sudo install -o root -g root -m 0755 /tmp/kubectl /usr/local/bin/kubectl && "
        "rm -f /tmp/kubectl",
    )


# ── database-forensics ───────────────────────────────────────────────────────
def database_mysql(r: CommandRunner) -> None:
    r.apt_install("mysql-client")


def database_postgres(r: CommandRunner) -> None:
    r.apt_install("postgresql-client")


def database_mongo(r: CommandRunner) -> None:
    r.pip_install("pymongo")


# ── email-forensics ──────────────────────────────────────────────────────────
def email_pst(r: CommandRunner) -> None:
    r.apt_install("libpst4", "pst-utils")


def email_eml(r: CommandRunner) -> None:
    r.pip_install("eml-parser")


def email_headers(r: CommandRunner) -> None:
    r.pip_install("mail-parser")


# ── osint-tools ──────────────────────────────────────────────────────────────
def osint_social(r: CommandRunner) -> None:
    r.pip_install("sherlock-project", "maigret")


def osint_email(r: CommandRunner) -> None:
    r.pip_install("holehe")


def osint_domain(r: CommandRunner) -> None:
    r.pip_install("theHarvester")
    r.apt_install("amass")


def osint_phone(r: CommandRunner) -> None:
    r.shell(
        "rm -rf /tmp/phoneinfoga && "
        "git clone --depth 1 https://github.com/sundowndev/phoneinfoga /tmp/phoneinfoga && "
        "sudo mv /tmp/phoneinfoga /opt/forensics/tools/phoneinfoga",
    )


# ── threat-intelligence ──────────────────────────────────────────────────────
def threat_iocs(r: CommandRunner) -> None:
    r.pip_install("pymisp", "OTXv2")


def threat_hunting(r: CommandRunner) -> None:
    r.pip_install("sigma-cli", "pysigma")


def threat_misp(r: CommandRunner) -> None:
    r.pip_install("pymisp")


def threat_opencti(r: CommandRunner) -> None:
    r.pip_install("pycti")


# ── web-recon ────────────────────────────────────────────────────────────────
def web_subdomain(r: CommandRunner) -> None:
    # subfinder ships precompiled binaries — preferred over the Go install path.
    r.shell(
        "URL=$(curl -fsSL https://api.github.com/repos/projectdiscovery/subfinder/releases/latest "
        "  | python3 -c \"import sys,json; "
        "    d=json.load(sys.stdin); "
        "    print(next((a['browser_download_url'] for a in d['assets'] "
        "                 if 'linux_amd64' in a['name'] and a['name'].endswith('.zip')), ''))\") && "
        "[ -n \"$URL\" ] && "
        "  curl -fsSL \"$URL\" -o /tmp/subfinder.zip && "
        "  unzip -qo /tmp/subfinder.zip -d /tmp/subfinder && "
        "  sudo install -o root -g root -m 0755 /tmp/subfinder/subfinder /usr/local/bin/subfinder && "
        "  rm -rf /tmp/subfinder /tmp/subfinder.zip",
    )


def web_scraping(r: CommandRunner) -> None:
    r.pip_install("scrapy", "beautifulsoup4")


def web_dns(r: CommandRunner) -> None:
    r.apt_install("dnsrecon", "dnsenum")


# ============================================================================
# Map (module, submodule) -> installer function
# ============================================================================

INSTALLERS: dict[str, dict[str, SubmoduleInstaller]] = {
    "cloud-forensics": {
        "aws-tools":     cloud_aws,
        "azure-tools":   cloud_azure,
        "gcp-tools":     cloud_gcp,
        "generic-cloud": cloud_generic,
    },
    "memory-forensics": {
        "volatility": memory_volatility,
        "lime":       memory_lime,
        "avml":       memory_avml,
    },
    "disk-forensics": {
        "sleuthkit": disk_sleuthkit,
        "testdisk":  disk_testdisk,
        "foremost":  disk_foremost,
        "scalpel":   disk_scalpel,
    },
    "network-forensics": {
        "wireshark": network_wireshark,
        "zeek":      network_zeek,
        "tcpdump":   network_tcpdump,
        "ngrep":     network_ngrep,
    },
    "mobile-forensics": {
        "android-tools":     mobile_android,
        "ios-tools":         mobile_ios,
        "backup-extractors": mobile_backup_extractors,
    },
    "malware-analysis": {
        "yara":    malware_yara,
        "radare2": malware_radare2,
        "ghidra":  malware_ghidra,
        "clamav":  malware_clamav,
    },
    "windows-forensics": {
        "regripper":       windows_regripper,
        "plaso":           windows_plaso,
        "evtx-parser":     windows_evtx,
        "prefetch-parser": windows_prefetch,
    },
    "linux-forensics": {
        "auditd-tools": linux_auditd,
        "log-parsers":  linux_log_parsers,
        "ext4-tools":   linux_ext4,
    },
    "container-forensics": {
        "docker-forensics": container_docker,
        "kubernetes-tools": container_kubernetes,
    },
    "database-forensics": {
        "mysql-tools":      database_mysql,
        "postgresql-tools": database_postgres,
        "mongodb-tools":    database_mongo,
    },
    "email-forensics": {
        "pst-parser":      email_pst,
        "eml-parser":      email_eml,
        "header-analyzer": email_headers,
    },
    "osint-tools": {
        "social-media": osint_social,
        "email-osint":  osint_email,
        "domain-recon": osint_domain,
        "phone-osint":  osint_phone,
    },
    "threat-intelligence": {
        "ioc-feeds":         threat_iocs,
        "threat-hunting":    threat_hunting,
        "misp-integration":  threat_misp,
        "opencti-tools":     threat_opencti,
    },
    "web-recon": {
        "subdomain-enum": web_subdomain,
        "web-scraping":   web_scraping,
        "dns-recon":      web_dns,
    },
}


# Removal commands — best-effort. Keys mirror INSTALLERS.
def _apt_remove(*pkgs: str) -> Iterator[list[str]]:
    yield ["sudo", "DEBIAN_FRONTEND=noninteractive",
           "apt-get", "remove", "-y", *pkgs]


def _pip_uninstall(*pkgs: str) -> Iterator[list[str]]:
    yield ["sudo", "pip3", "uninstall", "-y", *pkgs]


def _rm_path(path: str) -> Iterator[list[str]]:
    yield ["sudo", "rm", "-rf", path]


REMOVERS: dict[str, dict[str, list[list[str]]]] = {
    "memory-forensics":   {"volatility": list(_pip_uninstall("volatility3"))},
    "disk-forensics":     {"sleuthkit":  list(_apt_remove("sleuthkit")),
                           "testdisk":   list(_apt_remove("testdisk")),
                           "foremost":   list(_apt_remove("foremost")),
                           "scalpel":    list(_apt_remove("scalpel"))},
    "network-forensics":  {"wireshark":  list(_apt_remove("tshark", "wireshark-common")),
                           "tcpdump":    list(_apt_remove("tcpdump")),
                           "ngrep":      list(_apt_remove("ngrep", "tcpflow"))},
    "windows-forensics":  {"evtx-parser": list(_pip_uninstall("python-evtx")),
                           "prefetch-parser": list(_pip_uninstall("prefetch"))},
    "linux-forensics":    {"auditd-tools": list(_apt_remove("auditd", "audispd-plugins")),
                           "log-parsers":  list(_apt_remove("logwatch", "goaccess")),
                           "ext4-tools":   list(_apt_remove("e2fsprogs", "extundelete"))},
    "email-forensics":    {"pst-parser":   list(_apt_remove("libpst4", "pst-utils")),
                           "eml-parser":   list(_pip_uninstall("eml-parser")),
                           "header-analyzer": list(_pip_uninstall("mail-parser"))},
    "osint-tools":        {"social-media": list(_pip_uninstall("sherlock-project", "maigret")),
                           "email-osint":  list(_pip_uninstall("holehe")),
                           "domain-recon": list(_pip_uninstall("theHarvester"))},
    "malware-analysis":   {"yara":         list(_apt_remove("yara")),
                           "clamav":       list(_apt_remove("clamav"))},
    "mobile-forensics":   {"android-tools": list(_apt_remove("android-tools-adb",
                                                              "android-tools-fastboot"))},
    "database-forensics": {"mysql-tools":      list(_apt_remove("mysql-client")),
                           "postgresql-tools": list(_apt_remove("postgresql-client")),
                           "mongodb-tools":    list(_pip_uninstall("pymongo"))},
}
