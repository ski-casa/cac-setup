#!/usr/bin/env python3
"""Install DoD CAC certificates into Firefox/Chrome/Brave/Chromium NSS databases on Linux.

Usage:
    Requires sudo for package install and certutil/modutil
        - sudo python3 cac-setup.py [options]              # install CAC certs (default)
        - sudo python3 cac-setup.py --apply-crash-fix      # install certs AND apply the crash fix
        - sudo python3 cac-setup.py --add-pdf-signer       # install certs AND set up the PDF signer
    Run as your normal user, WITHOUT sudo
        - python3 cac-setup.py crash-fix [--revert]        # prlimit-wrap every Chromium browser (undo: --revert)
        - python3 cac-setup.py pdf-signer [--revert]       # install the GUI CAC PDF signer (undo: --revert)
        - python3 cac-setup.py trace-locks [nosandbox]     # diagnostic for the browser crash

``crash-fix`` also accepts the older ``browsers-crash-fix`` (and ``browser-crash-fix``) spellings.
The CAC-cert install -- and the ``--apply-crash-fix`` / ``--revert-crash-fix`` flags -- must run
as root via ``sudo``. The ``crash-fix`` and ``trace-locks`` subcommands must run as your
normal user WITHOUT sudo: they write launchers/logs into your home, so under sudo they would
leave root-owned files there (they now refuse to run as root). ``--apply-crash-fix`` runs the
cert install and then re-invokes the crash-fix rollout as the invoking user in one command --
the fresh-system setup. See the "Browser memory-lock crash fix" section for details.

What it does:
    1. Installs the packages needed for smartcard/CAC support (OpenSC, pcsc-lite,
       NSS ``certutil``/``modutil``, etc.) using the system package manager.
    2. Downloads the DoD certificate bundle from militarycac.com and unpacks it
       into ``/tmp/AllCerts``.
    3. For every browser NSS database found -- plus the shared ``~/.pki/nssdb``
       (created if absent), which non-browser NSS apps such as LibreOffice,
       poppler ``pdfsig`` and pyHanko also use -- registers the OpenSC PKCS#11
       module and imports the DoD trust anchors with trust ``CT,C,C`` so they
       validate both CAC web login (SSL) and document/email signing (S/MIME +
       object-signing). Re-runs also re-mark any certs left at an older
       SSL-only trust, so re-running upgrades an existing setup for signing.
    4. Creates a ``firefox-cac`` launcher/desktop entry for the CAC profile.
    5. (Optional, ``--disable-login-smartcard``) Stops the GDM login screen from
       switching to CAC/PIN auth when a card is inserted, without affecting
       browser CAC use or password login.

Office suites & CAC signing (gotcha): LibreOffice signs through NSS, so it reads
``~/.pki/nssdb`` and can sign with the CAC once this script has run (for GUI
launches also export ``MOZILLA_CERTIFICATE_FOLDER=~/.pki/nssdb``, e.g. via
``~/.config/environment.d/``). OnlyOffice does NOT use NSS -- it signs via OpenSSL
with a certificate/key *file* and has no PKCS#11/smartcard support, so it cannot
sign with a CAC on Linux no matter what this script does (the "Sign" action just
does nothing). For CAC signing use LibreOffice for documents, or pyHanko for PDFs.

Run ``python3 cac-setup.py --help`` for the available options.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import configparser
import os
import pwd
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import NamedTuple


# ============================================================================
# Configuration & constants
# ============================================================================

# Most of this script runs under ``sudo`` (the cert install and the
# ``--apply-crash-fix`` / ``--revert-crash-fix`` flags all need root -- they do
# the cert install, which is root-only). But those flags don't do the crash-fix
# work themselves: they re-invoke this script as the normal user (via
# ``sudo -u``) to run the ``crash-fix`` subcommand, so the launchers it writes
# land in -- and are owned by -- that user's home, not root's. See
# ``apply_crash_fix`` / ``revert_crash_fix``.
#
# The user-level subcommands (``crash-fix`` and ``trace-locks``) are that
# user-owned half on its own: they only write into the user's home, so they run
# as the normal user and refuse to run under sudo (see ``require_user``). So the
# crash fix always executes as the user -- whether you invoke ``crash-fix``
# directly, or reach it through the root ``--apply-crash-fix`` wrapper, which
# just bolts the root-only cert install onto the front.
#
# Resolve the *real* user for either case:
#   * When we're root (euid 0) we were sudo'd, so the human is named by
#     ``$SUDO_USER``.
#   * When we're NOT root we already ARE that user, so read our own uid -- and
#     crucially do NOT trust ``$SUDO_USER`` here. apply/revert re-invoke a
#     subcommand via ``sudo -u <user>``, and in that child ``$SUDO_USER`` is
#     ``root`` (it names whoever called sudo -- the root process), which would
#     otherwise resolve ORIG_HOME to /root and write launchers into the wrong home.
if os.geteuid() == 0:
    ORIG_USER = (
        os.environ.get('SUDO_USER')
        or os.environ.get('LOGNAME')
        or os.environ.get('USER')
        or pwd.getpwuid(0).pw_name
    )
else:
    ORIG_USER = pwd.getpwuid(os.getuid()).pw_name
ORIG_HOME = Path(pwd.getpwnam(ORIG_USER).pw_dir)

# Where the DoD certificate bundle is downloaded and unpacked.
CERT_URL = 'https://militarycac.com/maccerts/AllCerts.zip'
ZIP_PATH = Path('/tmp/AllCerts.zip')
CERT_DIR = Path('/tmp/AllCerts')

# Common install locations of the OpenSC PKCS#11 module, in priority order.
# Some distros ship it directly under the arch libdir, others only under a
# ``pkcs11/`` subdirectory (the p11-kit module path), so both are checked.
PKCS11_PATHS = (
    '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so',
    '/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so',
    '/usr/lib64/opensc-pkcs11.so',
    '/usr/lib64/pkcs11/opensc-pkcs11.so',
    '/usr/lib/opensc-pkcs11.so',
    '/usr/lib/pkcs11/opensc-pkcs11.so',
    '/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so',
    '/usr/lib/aarch64-linux-gnu/pkcs11/opensc-pkcs11.so',
)

# Trust flags applied to every imported DoD CA. NSS trust has three columns:
# SSL, S/MIME, and object-signing. ``CT,C,C`` marks each CA trusted in all
# three, so the same anchors validate CAC *web login* (SSL) AND *document/email
# signing* (S/MIME) -- e.g. signing PDFs in LibreOffice/pyHanko or S/MIME mail.
# (SSL-only ``TC,,`` is enough for browsing but makes signatures show untrusted.)
CERT_TRUST = 'CT,C,C'

# profiles.ini lives in different places depending on how Firefox was installed
# (traditional/apt, distro variants, snap, flatpak). Checked in this order.
FIREFOX_INI_CANDIDATES = (
    '.mozilla/firefox/profiles.ini',
    '.config/mozilla/firefox/profiles.ini',
    'snap/firefox/common/.mozilla/firefox/profiles.ini',
    '.var/app/org.mozilla.firefox/.mozilla/firefox/profiles.ini',
)

# Packages required for CAC support, keyed by package manager.
PKG_SET = {
    'apt': ['libpcsclite1', 'pcscd', 'libccid', 'libpcsc-perl', 'pcsc-tools', 'libnss3-tools', 'unzip', 'wget', 'opensc', 'python3-venv', 'zenity'],
    'dnf': ['pcsc-lite', 'pcsc-lite-ccid', 'pcsc-tools', 'nss-tools', 'opensc', 'unzip', 'wget'],
    'yum': ['pcsc-lite', 'pcsc-lite-ccid', 'pcsc-tools', 'nss-tools', 'opensc', 'unzip', 'wget'],
    'zypper': ['ccid', 'pcsc-tools', 'mozilla-nss-tools', 'opensc', 'unzip', 'wget'],
}

# Environment for child processes: never let apt prompt interactively.
ENV = {**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}

# Runtime flags, set from the parsed CLI arguments in main().
DRY_RUN = False
VERBOSE = False

# Serializes log() so concurrent worker threads don't interleave output.
LOG_LOCK = threading.Lock()


class DBResult(NamedTuple):
    """Outcome of updating a single NSS database."""

    db: str
    imported: int
    duration: float


# ============================================================================
# Logging
# ============================================================================

def log(msg: str) -> None:
    """Print a user-visible progress line, prefixed and thread-safe."""
    with LOG_LOCK:
        print(f'[cac-setup] {msg}')


# ============================================================================
# Privilege / subprocess helpers
# ============================================================================

def require_root() -> None:
    """Exit unless the script is running as root (needed for package install)."""
    if os.geteuid() != 0:
        raise SystemExit('run this script as root')


def require_user(subcommand: str) -> None:
    """Exit if running as root: the user-level subcommands must NOT be sudo'd.

    ``crash-fix`` and ``trace-locks`` write launchers/logs into the
    invoking user's home (and ``trace-locks`` runs the browser). Under sudo they
    would leave root-owned files in ~ that the user can't edit or delete, or run
    Chrome as root -- so refuse with a hint instead of doing that silently. The
    apply/revert paths re-invoke these via ``sudo -u <user>``, i.e. as non-root,
    so this guard does not interfere with them.
    """
    if os.geteuid() == 0:
        raise SystemExit(
            f"run '{subcommand}' as your normal user, WITHOUT sudo -- it writes "
            f"into your home directory.\n    python3 cac-setup.py {subcommand}"
        )


def _detach_tty(kw: dict) -> dict:
    """Detach a child process from the controlling terminal.

    sudo 1.9.14+ enables ``use_pty`` by default: it runs each command in a pty
    and flips the *real* terminal into raw mode (OPOST/ONLCR off) while the
    command runs, restoring it on exit. Because we run several of these
    concurrently (``--max-workers``), they race on that save/restore and
    intermittently leave the terminal raw, garbling log output. Giving sudo a
    non-tty stdin and a new session removes the real tty it would manipulate.
    """
    kw.setdefault('stdin', subprocess.DEVNULL)
    kw.setdefault('start_new_session', True)
    return kw


def sudo_user(*cmd: str, **kw) -> subprocess.CompletedProcess:
    """Run ``cmd`` as the original (non-root) user via sudo."""
    return subprocess.run(('sudo', '-H', '-u', ORIG_USER) + cmd, text=True, env=ENV, **_detach_tty(kw))


def sudo_user_shell(script: str, **kw) -> subprocess.CompletedProcess:
    """Run a bash ``script`` as the original user via sudo (login shell)."""
    return subprocess.run(
        ('sudo', '-H', '-u', ORIG_USER, 'bash', '-lc', script),
        text=True,
        env=ENV,
        **_detach_tty(kw),
    )


def package_manager() -> str | None:
    """Return the first supported package manager found on PATH, or None."""
    for cmd in ('apt', 'dnf', 'yum', 'zypper'):
        if shutil.which(cmd):
            return cmd
    return None


def find_pkcs11() -> str:
    """Return the path to the OpenSC PKCS#11 module, or exit if not installed."""
    for path in PKCS11_PATHS:
        if Path(path).exists():
            return path
    raise SystemExit('OpenSC PKCS#11 module not found; install opensc or adjust PKCS11_PATHS.')


# ============================================================================
# CLI
# ============================================================================

def parse_args() -> argparse.Namespace:
    """Define and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Install DoD CAC certificates into Firefox/Chrome/Brave/Chromium NSS databases.'
    )
    parser.add_argument('-n', '--dry-run', action='store_true',
                        help='Show what would be done without changing anything')
    parser.add_argument('--max-workers', type=int, default=0,
                        help='Maximum number of parallel workers for separate NSS databases (0 = auto)')
    parser.add_argument('--only-browsers', type=str, default='',
                        help='Comma-separated browser identifiers to restrict updates to (e.g. firefox,chrome,brave,pki)')
    parser.add_argument('--exclude-browsers', type=str, default='',
                        help='Comma-separated browser identifiers to exclude')
    parser.add_argument('--create-launcher', action='store_true',
                        help='Also create a separate "firefox-cac" launcher/desktop entry that opens '
                             'the existing default profile (not needed; certs are imported into your '
                             'normal profile directly)')
    parser.add_argument('--disable-login-smartcard', action='store_true',
                        help='Stop the GDM login screen from prompting for the CAC/PIN when a '
                             'card is inserted (browser CAC use and password login are '
                             'unaffected). GDM/dconf only; takes effect after a reboot.')
    parser.add_argument('--apply-crash-fix', action='store_true',
                        help='After installing certs, also apply the browser memory-lock crash '
                             'fix: prlimit-wrap every Chromium-family browser (Chrome included). '
                             'Runs as your user. Use this for a one-command fresh-system setup.')
    parser.add_argument('--revert-crash-fix', action='store_true',
                        help='Undo the crash fix (remove the per-browser .desktop overrides), '
                             'then exit without installing certs.')
    parser.add_argument('--add-pdf-signer', action='store_true',
                        help='After installing certs, also set up the GUI CAC PDF signer '
                             '(pyHanko venv + script + "Sign PDF with CAC" launcher). Runs as '
                             'your user. Signs existing signature blocks in PDFs.')
    parser.add_argument('--remove-pdf-signer', action='store_true',
                        help='Remove the CAC PDF signer (venv + script + launcher), then exit '
                             'without installing certs.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show more detailed progress messages')
    return parser.parse_args()


# ============================================================================
# Package install & certificate download
# ============================================================================

def install_packages() -> None:
    """Install the smartcard/CAC and NSS utility packages for this distro."""
    pm = package_manager()
    if not pm:
        raise SystemExit('No supported package manager found; install required packages manually.')
    if DRY_RUN:
        log(f'[DRY RUN] Would install packages with {pm}: {PKG_SET[pm]}')
        return
    log(f'Installing required packages with {pm}...')
    if pm == 'apt':
        subprocess.run(('apt', 'update'), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
        subprocess.run(('apt', 'install', '-y', *PKG_SET['apt']), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
    elif pm in ('dnf', 'yum'):
        subprocess.run((pm, 'install', '-y', *PKG_SET[pm]), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
    else:  # zypper
        subprocess.run((pm, 'install', '-yn', *PKG_SET[pm]), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
    log('Package installation complete.')


def download_certs() -> None:
    """Download the DoD certificate bundle and unpack it into CERT_DIR.

    Files are extracted world-readable and chowned to the original user so the
    later certutil import (run as that user) can read them.
    """
    if DRY_RUN:
        log(f'[DRY RUN] Would download DoD certificates to {ZIP_PATH} and extract them to {CERT_DIR}.')
        return
    log(f'Downloading DoD certificates to {ZIP_PATH}...')
    ZIP_PATH.unlink(missing_ok=True)
    urllib.request.urlretrieve(CERT_URL, ZIP_PATH)
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ZIP_PATH) as z:
        z.extractall(CERT_DIR)
    for p in CERT_DIR.iterdir():
        p.chmod(0o644)
    shutil.chown(CERT_DIR, ORIG_USER, ORIG_USER)
    for p in CERT_DIR.rglob('*'):
        shutil.chown(p, ORIG_USER, ORIG_USER)
    log(f'Certificates unpacked into {CERT_DIR}.')


# ============================================================================
# Firefox profile discovery
#
# Modern Firefox (67+) keeps a dedicated profile *per installation*, recorded in
# profiles.ini under ``[Install<hash>]`` sections. The legacy ``[Profile*]
# Default=1`` flag is only a fallback, so we resolve installs first.
# ============================================================================

def _read_all_profiles_ini() -> list[tuple[Path, configparser.RawConfigParser]]:
    """Locate and parse *every* profiles.ini present.

    A machine can have more than one Firefox install at once (e.g. the snap and
    a deb side by side), each with its own profiles.ini in a different location.
    Returning only the first match means certs get imported into a profile the
    running browser never opens, so we collect them all.
    """
    results = []
    for rel in FIREFOX_INI_CANDIDATES:
        ini = ORIG_HOME / rel
        if ini.exists():
            cfg = configparser.RawConfigParser()
            cfg.read(ini)
            results.append((ini, cfg))
    return results


def _profile_path(ini: Path, cfg: configparser.RawConfigParser, section: str) -> Path | None:
    """Resolve a ``[Profile*]`` section's ``Path`` to an absolute directory."""
    path = cfg.get(section, 'Path', fallback='')
    if not path:
        return None
    if cfg.get(section, 'IsRelative', fallback='1') == '1':
        return (ini.parent / path).resolve()
    return Path(path)


def firefox_profiles() -> list[Path]:
    """Return every Firefox profile directory referenced by any profiles.ini."""
    profiles = []
    for ini, cfg in _read_all_profiles_ini():
        for section in cfg.sections():
            if section.startswith('Profile'):
                profile = _profile_path(ini, cfg, section)
                if profile:
                    profiles.append(profile)
    return list(dict.fromkeys(profiles))  # de-duplicate, preserving order


def firefox_default_profiles() -> list[Path]:
    """Return the default profile of every Firefox install on the machine.

    For each profiles.ini found, resolve the profile Firefox actually opens:
    the per-installation default (``[Install<hash>] Default``), then the legacy
    ``[Profile*] Default=1`` flag, then the first profile defined. With multiple
    installs (e.g. snap + deb) this yields one default per install.
    """
    defaults = []
    for ini, cfg in _read_all_profiles_ini():
        chosen = None
        # 1. Per-installation dedicated default profile (relative to the ini dir).
        for section in cfg.sections():
            if section.startswith('Install'):
                rel = cfg.get(section, 'Default', fallback='')
                if rel:
                    chosen = (ini.parent / rel).resolve()
                    break
        # 2. Legacy Default=1 flag.
        if chosen is None:
            for section in cfg.sections():
                if section.startswith('Profile') and cfg.get(section, 'Default', fallback='0') == '1':
                    chosen = _profile_path(ini, cfg, section)
                    break
        # 3. Fallback: the first profile defined in this ini.
        if chosen is None:
            for section in cfg.sections():
                if section.startswith('Profile'):
                    chosen = _profile_path(ini, cfg, section)
                    break
        if chosen:
            defaults.append(chosen)
    return list(dict.fromkeys(defaults))


# ============================================================================
# NSS database update (certificate import + OpenSC registration)
# ============================================================================

def list_existing_certs(db: str) -> dict[str, str]:
    """Return ``{nickname: trust_flags}`` for certs already present in an NSS db.

    The trust flags let a re-run detect certs imported with the wrong trust
    (e.g. an older SSL-only ``TC,,``) and re-mark them to CERT_TRUST.
    """
    proc = sudo_user('certutil', '-L', '-d', f'sql:{db}', capture_output=True)
    if proc.returncode:
        return {}
    certs: dict[str, str] = {}
    for line in proc.stdout.splitlines()[2:]:  # skip the two header lines
        if not line.strip():
            continue
        # Format is "<nickname>   <trust>"; the trust column is the final token
        # and always contains commas (e.g. CT,C,C / u,u,u). If the last token
        # doesn't look like trust flags, treat the whole line as the nickname.
        nick, sep, trust = line.rpartition(' ')
        nick, trust = nick.strip(), trust.strip()
        if not sep or ',' not in trust:
            nick, trust = line.strip(), ''
        if nick:
            certs[nick] = trust
    return certs


def import_certs(db: str) -> DBResult | None:
    """Import the DoD certs into one NSS database and register OpenSC.

    Initializes the database if missing/invalid, imports only the certificates
    not already present (so re-runs are fast), then registers the OpenSC PKCS#11
    module last -- keeping the CAC out of the ~45 import calls, which would
    otherwise each block on the card. Returns a DBResult, or None in dry-run mode.
    """
    start_time = time.monotonic()
    log(f'Updating NSS database at {db}...')

    if DRY_RUN:
        log(f'[DRY RUN] Would initialize or verify NSS database at {db}.')
        certs = sorted(CERT_DIR.glob('*.cer'))
        if certs:
            for cert in certs:
                nick = cert.stem.replace(' ', '_')
                log(f'[DRY RUN] Would import {cert.name} as {nick} (trust {CERT_TRUST})')
        else:
            log(f'[DRY RUN] Would import certificate files from {CERT_DIR} if present.')
        log(f'[DRY RUN] Would register OpenSC module from {PKCS11_PATHS}.')
        return None

    pkcs11 = find_pkcs11()

    # Initialize a fresh database if the existing one is missing or unreadable.
    if sudo_user('certutil', '-L', '-d', f'sql:{db}', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        log('NSS database missing or invalid, initializing a new one.')
        for name in ('cert9.db', 'key4.db', 'pkcs11.txt'):
            (Path(db) / name).unlink(missing_ok=True)
        sudo_user('certutil', '-d', f'sql:{db}', '-N', '--empty-password',
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).check_returncode()

    # Make sure OpenSC is NOT registered while we import the certs. Importing CA
    # anchors never needs the card, but if the module is registered every one of
    # the ~45 certutil calls re-initializes NSS, loads OpenSC and wakes the
    # inserted CAC through pcscd -- each call then blocks for seconds on the card,
    # turning a seconds-long job into many minutes (worse with several DBs
    # contending on one reader). So we drop any registration left by a previous
    # run now, and add OpenSC back exactly once, at the end.
    sudo_user('modutil', '-dbdir', f'sql:{db}', '-delete', 'OpenSC', '-force',
              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    dbdir = f'sql:{db}'
    existing = list_existing_certs(db)

    # Split the bundle into certs not present yet (import) and certs already
    # present but with the wrong trust (re-mark). Re-marking lets a re-run
    # upgrade older SSL-only (TC,,) imports to CERT_TRUST -- so document/email
    # signing starts working -- without a delete+re-add.
    certs_to_import = []
    nicks_to_retrust = []
    for cert in sorted(CERT_DIR.glob('*.cer')):
        nick = cert.stem.replace(' ', '_')
        if nick not in existing:
            certs_to_import.append((cert, nick))
        elif existing[nick] != CERT_TRUST:
            nicks_to_retrust.append(nick)

    # Import/re-mark only what changed. Batch every certutil call into a single
    # sudo shell to avoid the per-call sudo overhead; ``set -e`` aborts on the
    # first failure. New certs get CERT_TRUST; already-present ones are re-marked.
    # With OpenSC not yet registered (above), none of these calls touch the card.
    if certs_to_import or nicks_to_retrust:
        script = ['set -e']
        for cert, nick in certs_to_import:
            script.append(
                f'certutil -d {shlex.quote(dbdir)} -A -n {shlex.quote(nick)} '
                f'-t {CERT_TRUST} -i {shlex.quote(str(cert))}'
            )
        for nick in nicks_to_retrust:
            script.append(
                f'certutil -d {shlex.quote(dbdir)} -M -n {shlex.quote(nick)} -t {CERT_TRUST}'
            )
        sudo_user_shell('\n'.join(script),
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).check_returncode()

    # Register OpenSC last, after all certutil work -- so the imports above never
    # had to touch the card. This single call is the only card interaction.
    sudo_user('modutil', '-dbdir', f'sql:{db}', '-add', 'OpenSC', '-libfile', pkcs11, '-force',
              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    duration = time.monotonic() - start_time
    imported = len(certs_to_import)
    retrusted = len(nicks_to_retrust)
    log(f'{db}: imported {imported} new, re-trusted {retrusted}, registered OpenSC '
        f'({duration:.2f}s).')
    return DBResult(db, imported, duration)


def ensure_pki_nssdb() -> Path:
    """Ensure the shared ``~/.pki/nssdb`` directory exists, creating it if absent.

    This is the default NSS database for Chrome/Chromium *and* for non-browser
    NSS consumers (LibreOffice, poppler ``pdfsig``, pyHanko, S/MIME mail, ...).
    On a fresh machine it may not exist yet, so we create the directory (owned by
    the real user); ``import_certs`` then initializes the actual db files and
    registers OpenSC. Returns the path regardless.
    """
    nssdb = ORIG_HOME / '.pki/nssdb'
    if nssdb.exists():
        return nssdb
    if DRY_RUN:
        log(f'[DRY RUN] Would create shared NSS database directory {nssdb}.')
        return nssdb
    nssdb.mkdir(parents=True, exist_ok=True)
    # Own the whole ~/.pki tree we may have just created by the real user, so the
    # later certutil/modutil calls (run as that user via sudo) can write to it.
    shutil.chown(nssdb, ORIG_USER, ORIG_USER)
    shutil.chown(nssdb.parent, ORIG_USER, ORIG_USER)
    log(f'Created shared NSS database directory {nssdb}.')
    return nssdb


def browser_databases() -> list[str]:
    """Return every NSS database root to update.

    Includes *all* Firefox profiles (the active one is install-dependent, so we
    populate them all), the shared ``~/.pki/nssdb`` (always -- see
    ``ensure_pki_nssdb``), plus the Chromium/Brave/Chrome and shared PKI
    databases that exist on disk.
    """
    roots = [str(profile) for profile in firefox_profiles()]
    # Always include the shared user NSS db; ensure_pki_nssdb() guarantees the
    # directory exists and import_certs() initializes it if the files are absent.
    roots.append(str(ORIG_HOME / '.pki/nssdb'))
    for candidate in (
        ORIG_HOME / '.config/chromium',
        ORIG_HOME / '.config/BraveSoftware/Brave-Browser',
        ORIG_HOME / '.config/google-chrome',
        ORIG_HOME / '.local/share/pki',
    ):
        if candidate.exists():
            roots.append(str(candidate))
    return list(dict.fromkeys(roots))  # de-duplicate, preserving order


# ============================================================================
# Profile initialization (create profiles before importing into them)
# ============================================================================

def init_firefox_profile() -> None:
    """Create the default Firefox profile by launching it headless, if missing."""
    if DRY_RUN:
        log('[DRY RUN] Would initialize Firefox profile if needed.')
        return
    profiles = firefox_default_profiles()
    existing = [p for p in profiles if Path(p).exists()]
    if existing:
        for p in existing:
            log(f'Firefox profile directory exists at {p}.')
        return
    log('No Firefox profile directory found; initializing by running Firefox headless...')
    sudo_user('pkill', '-9', 'firefox', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    # Background a headless Firefox just long enough to create the profile.
    sudo_user_shell('firefox --headless --first-startup >/dev/null 2>&1 &',
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    sudo_user('pkill', '-9', 'firefox', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    log('Firefox profile initialized.')


def init_chrome_profile() -> None:
    """Create Chromium/Brave/Chrome default profiles by launching headless, if missing."""
    if DRY_RUN:
        log('[DRY RUN] Would initialize Chrome profile if needed.')
        return
    browsers = [
        ('Chromium', ORIG_HOME / '.config/chromium', 'chromium'),
        ('Brave', ORIG_HOME / '.config/BraveSoftware/Brave-Browser', 'brave-browser'),
        ('Google Chrome', ORIG_HOME / '.config/google-chrome', 'google-chrome'),
    ]
    for browser_name, browser_path, exe in browsers:
        if browser_path.exists() and not (browser_path / 'Default').exists():
            log(f'{browser_name} profile directory does not exist; initializing...')
            sudo_user('pkill', '-9', exe, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
            sudo_user_shell(f'{exe} --headless --disable-gpu >/dev/null 2>&1 &',
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3)
            sudo_user('pkill', '-9', exe, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
            log(f'{browser_name} profile initialized.')


# ============================================================================
# Post-import: smartcard daemon, verification, launcher, restart
# ============================================================================

def connect_snap_firefox_pcscd() -> None:
    """If Firefox is a snap, connect its ``pcscd`` interface.

    The Firefox snap ships a ``pcscd`` plug but leaves it disconnected, so the
    confined browser cannot reach the smartcard daemon and the CAC never shows
    up no matter how the NSS database is populated. No-op for a deb/non-snap
    Firefox.
    """
    if not shutil.which('snap'):
        return
    if subprocess.run(('snap', 'list', 'firefox'),
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        return
    if DRY_RUN:
        log('[DRY RUN] Would connect snap interface firefox:pcscd.')
        return
    log('Firefox snap detected; connecting firefox:pcscd interface...')
    subprocess.run(('snap', 'connect', 'firefox:pcscd'),
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def ensure_pcscd() -> None:
    """Start the pcscd smartcard daemon, required to read the CAC at runtime."""
    if DRY_RUN:
        log('[DRY RUN] Would ensure pcscd daemon is running.')
        return
    log('Ensuring pcscd daemon is running...')
    subprocess.run(('systemctl', 'start', 'pcscd'), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    proc = subprocess.run(('systemctl', 'is-active', 'pcscd'), capture_output=True, text=True)
    if proc.returncode == 0:
        log('pcscd daemon is running.')
    else:
        log('WARNING: pcscd daemon failed to start. Certificate validation may not work.')


def verify_certs(db: str) -> int:
    """Return the certificate count in an NSS db, logging them when verbose."""
    if DRY_RUN:
        log('[DRY RUN] Would verify certificates in database.')
        return 0
    proc = sudo_user('certutil', '-L', '-d', f'sql:{db}', capture_output=True, text=True)
    if proc.returncode != 0:
        return 0
    lines = proc.stdout.strip().split('\n')
    cert_count = max(0, len(lines) - 2)  # skip the two header lines
    if VERBOSE and cert_count > 0:
        log(f'Found {cert_count} certificates in {db}:')
        for line in lines[2:]:
            if line.strip():
                log(f'  {line}')
    return cert_count


def create_launcher(profile: Path) -> None:
    """Create a ``firefox-cac`` launcher script and matching .desktop entry."""
    bin_dir = ORIG_HOME / '.local/bin'
    app_dir = ORIG_HOME / '.local/share/applications'
    launcher = bin_dir / 'firefox-cac'
    desktop = app_dir / 'firefox-cac.desktop'
    if DRY_RUN:
        log(f'[DRY RUN] Would create launcher at {launcher} and desktop entry at {desktop}.')
        return
    bin_dir.mkdir(parents=True, exist_ok=True)
    app_dir.mkdir(parents=True, exist_ok=True)
    launcher.write_text(f"#!/usr/bin/env bash\nexec firefox --profile '{profile}' -no-remote \"$@\"\n")
    desktop.write_text(
        "[Desktop Entry]\n"
        "Name=Firefox CAC\n"
        "Comment=Launch Firefox with DoD CAC profile\n"
        f"Exec={launcher}\n"
        "Terminal=false\nType=Application\nCategories=Network;WebBrowser;\nStartupNotify=true\n"
    )
    launcher.chmod(0o755)
    desktop.chmod(0o644)
    shutil.chown(launcher, ORIG_USER, ORIG_USER)
    shutil.chown(desktop, ORIG_USER, ORIG_USER)


def restart_firefox() -> None:
    """Kill any running Firefox so it reloads the updated NSS database."""
    if DRY_RUN:
        log('[DRY RUN] Would restart Firefox to reload certificate database.')
        return
    log('Restarting Firefox to reload certificate database...')
    sudo_user('pkill', '-9', 'firefox', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    log('Firefox process terminated.')


# ============================================================================
# Optional: disable CAC/smartcard authentication at the GDM login screen
# ============================================================================

# The GDM greeter reads its dconf settings through the ``gdm`` profile. Ubuntu/
# Debian ship it at /usr/share with only ``user-db`` + ``file-db`` lines, so a
# plain /etc/dconf/db/gdm.d/ keyfile is ignored until the profile also names a
# ``system-db``. We add that, then turn off the login-screen smartcard prompt.
GDM_DCONF_PROFILE = Path('/etc/dconf/profile/gdm')
GDM_DCONF_PROFILE_DEFAULT = Path('/usr/share/dconf/profile/gdm')
GDM_DCONF_KEYFILE = Path('/etc/dconf/db/gdm.d/00-disable-smartcard')
GDM_KEYFILE_CONTENT = (
    '# Added by cac-setup.py --disable-login-smartcard\n'
    '# Stops the GDM login screen from switching to CAC/PIN when a card is\n'
    '# inserted. Browser CAC use (NSS/PKCS#11) and password login are unaffected.\n'
    '[org/gnome/login-screen]\n'
    'enable-smartcard-authentication=false\n'
)


def _gdm_profile_with_system_db() -> str:
    """Return greeter dconf-profile text guaranteed to include ``system-db:gdm``.

    Starts from the existing /etc override or the /usr/share distro default so we
    preserve the distro's ``file-db`` line, then inserts ``system-db:gdm`` right
    after ``user-db:user`` if absent. Falls back to the canonical Ubuntu layout
    when no profile exists at all.
    """
    base = ''
    for src in (GDM_DCONF_PROFILE, GDM_DCONF_PROFILE_DEFAULT):
        if src.exists():
            base = src.read_text()
            break
    lines = [ln.rstrip() for ln in base.splitlines() if ln.strip()]
    if not lines:
        lines = ['user-db:user', 'file-db:/var/lib/gdm3/greeter-dconf-defaults']
    if 'system-db:gdm' not in lines:
        idx = next((i for i, ln in enumerate(lines) if ln.startswith('user-db:')), -1)
        lines.insert(idx + 1, 'system-db:gdm')
    return '\n'.join(lines) + '\n'


def disable_login_smartcard() -> None:
    """Stop the GDM login screen from using the CAC reader (opt-in).

    GNOME's greeter switches to smartcard/PIN auth when a CAC is inserted,
    governed by ``org.gnome.login-screen enable-smartcard-authentication``. This
    disables it for the greeter only; the user's password login and every
    browser's CAC use are untouched. No-op on systems without GDM/dconf.
    """
    if not shutil.which('dconf') or not (
        GDM_DCONF_PROFILE.exists() or GDM_DCONF_PROFILE_DEFAULT.exists()
    ):
        log('GDM/dconf not detected; skipping login-screen smartcard disable.')
        return
    if DRY_RUN:
        log(f'[DRY RUN] Would write {GDM_DCONF_PROFILE} (adding system-db:gdm) and '
            f'{GDM_DCONF_KEYFILE}, then run `dconf update`.')
        return
    log('Disabling CAC/smartcard authentication at the GDM login screen...')
    GDM_DCONF_PROFILE.write_text(_gdm_profile_with_system_db())
    GDM_DCONF_KEYFILE.parent.mkdir(parents=True, exist_ok=True)
    GDM_DCONF_KEYFILE.write_text(GDM_KEYFILE_CONTENT)
    if subprocess.run(('dconf', 'update'), env=ENV).returncode == 0:
        log('Login-screen smartcard disabled. Reboot (or restart gdm) to apply.')
    else:
        log('WARNING: `dconf update` failed; login-screen smartcard not disabled.')


# ============================================================================
# Browser memory-lock crash fix: launcher, rollout, and diagnostics
#
# Chromium-family browsers mlock() pages inside PartitionAlloc's heap during TLS
# handshakes (including CAC authentication). When PartitionAlloc later decommits
# a span overlapping a still-locked page, madvise(MADV_DONTNEED) returns EINVAL
# and the browser makes it FATAL -> a recurring crash, independent of distro,
# kernel, or Chrome version (confirmed via strace, 2026-06). Launching with
# RLIMIT_MEMLOCK=0 makes those mlock()s fail harmlessly (crypto libs fall back to
# unlocked memory), so no page is ever VM_LOCKED and the fault cannot occur. The
# CAC private key never leaves the card, so the security impact is negligible.
#
# These subcommands run as the NORMAL user (no sudo):
#   cac-setup.py crash-fix [--revert]           # prlimit-wrap every Chromium-family browser
#   cac-setup.py trace-locks [nosandbox]        # diagnostic: trace mlock() during a crash
# (``crash-fix`` also accepts the older ``browsers-crash-fix`` / ``browser-crash-fix`` spellings.)
#
# The root install path can drive the rollout with ``--apply-crash-fix`` (and undo it with
# ``--revert-crash-fix``); both re-invoke ``crash-fix`` AS THE INVOKING USER, so the
# generated ~/.local/share/applications launchers are user-owned, not root-owned.
# ============================================================================

# Chrome binary path, kept for the trace-locks diagnostic below.
CHROME_BIN = '/usr/bin/google-chrome-stable'


# Per-browser rollout: wrap each Chromium-family .desktop with `prlimit --memlock=0`,
# which caps the browser process's RLIMIT_MEMLOCK at 0 -- the crash fix. Chrome is
# wrapped the same way as every other browser (no bespoke launcher), so one command
# covers the whole family uniformly.
_FIX_USER_APPS = ORIG_HOME / '.local/share/applications'
_FIX_MARKER = 'X-Memlock-Fix=generated'
_FIX_WRAP = 'prlimit --memlock=0 --'
_FIX_SOURCE_DIRS = (
    Path('/usr/share/applications'),
    Path('/var/lib/snapd/desktop/applications'),
    Path('/var/lib/flatpak/exports/share/applications'),
    ORIG_HOME / '.local/share/flatpak/exports/share/applications',
)
_FIX_BROWSER_IDS = (
    'google-chrome', 'google-chrome-stable',
    'chromium', 'chromium-browser', 'chromium_chromium', 'brave-browser',
    'microsoft-edge', 'microsoft-edge-beta', 'microsoft-edge-dev',
    'vivaldi-stable', 'opera', 'opera-beta',
)


def _fix_find_source(bid: str) -> Path | None:
    """Return the first system/snap/flatpak .desktop for a browser id, if present."""
    for d in _FIX_SOURCE_DIRS:
        p = d / f'{bid}.desktop'
        if p.is_file():
            return p
    return None


def _fix_wrap_override(src: Path) -> str:
    """Copy a .desktop, prefixing each Exec= with the prlimit wrapper + a marker."""
    out: list[str] = []
    for line in src.read_text().splitlines():
        if line.startswith('Exec='):
            cmd = line[len('Exec='):].strip()
            if not cmd.startswith('prlimit'):
                line = f'Exec={_FIX_WRAP} {cmd}'
        out.append(line)
        if line.startswith('[Desktop'):  # tag each section so --revert can find it
            out.append(_FIX_MARKER)
    return '\n'.join(out) + '\n'


def _fix_update_db() -> None:
    subprocess.run(f'update-desktop-database {shlex.quote(str(_FIX_USER_APPS))} 2>/dev/null',
                   shell=True)


def cmd_browsers_crash_fix(argv: list[str]) -> None:
    """Apply (or --revert) the memlock crash fix to every Chromium-family browser.

    For each installed browser (Chrome, Chromium, Brave, Edge, Vivaldi, Opera, ...)
    writes a per-user .desktop override that prefixes every ``Exec=`` with
    ``prlimit --memlock=0 --``, so the browser starts with RLIMIT_MEMLOCK=0 and the
    smartcard/TLS mlock crash cannot occur. Runs as the normal user.
    """
    require_user('crash-fix')
    if '--revert' in argv:
        removed = 0
        for p in _FIX_USER_APPS.glob('*.desktop'):
            try:
                if _FIX_MARKER in p.read_text():
                    p.unlink()
                    removed += 1
                    print(f'  removed {p}')
            except OSError:
                pass
        _fix_update_db()
        print(f'Reverted {removed} override(s).')
        return

    dry = '--dry-run' in argv
    _FIX_USER_APPS.mkdir(parents=True, exist_ok=True)
    acted = 0
    for bid in _FIX_BROWSER_IDS:
        src = _fix_find_source(bid)
        if not src:
            continue
        dest = _FIX_USER_APPS / f'{bid}.desktop'
        print(f'  {bid}: {"would wrap" if dry else "wrapped"}  ({src})')
        if not dry:
            dest.write_text(_fix_wrap_override(src))
        acted += 1
    if acted and not dry:
        _fix_update_db()
    if acted == 0:
        print('  (no Chromium-family browsers installed)')
    print(f'{"Would apply" if dry else "Applied"} to {acted} browser(s). Fully relaunch each, '
          'then verify:  grep "Max locked memory" /proc/$(pgrep -x <browser> | head -1)/limits')


def cmd_trace_locks(argv: list[str]) -> None:
    """Diagnostic: run Chrome under strace and capture mlock() calls during a crash."""
    require_user('trace-locks')
    if not shutil.which('strace'):
        raise SystemExit('strace not installed:  sudo apt install strace')
    log_path = ORIG_HOME / 'chrome-lock-trace.log'
    subprocess.run(['pkill', '-TERM', '-f', '/opt/google/chrome/chrome'])
    time.sleep(2)
    log_path.write_text('')
    print(f'Launching Chrome under trace -> {log_path}\n'
          'Reproduce the crash (e.g. CAC auth), then return here.')
    cmd = ['strace', '-f', '-tt', '-y',
           '-e', 'trace=mlockall,munlockall,mlock,mlock2,munlock',
           '-o', str(log_path), CHROME_BIN]
    if 'nosandbox' in argv:
        cmd.append('--no-sandbox')
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f'\nChrome exited. Lock calls captured in {log_path}:')
    subprocess.run(r"grep -hoE '\b(mlockall|mlock2|mlock|munlockall|munlock)\(' "
                   f"{shlex.quote(str(log_path))} | tr -d '(' | sort | uniq -c", shell=True)


# ============================================================================
# PDF signer setup: a GUI CAC PDF signer (pyHanko) installed into the user's home
#
# Signs an EXISTING signature block in a PDF with the CAC -- the one thing
# JSignPdf / LibreOffice / OnlyOffice can't do on Linux (they add a new/invisible
# signature and leave the pre-placed block empty). Installed as a user-level tool
# (a venv with pyHanko+pypdf, the signer script in ~/bin, and an app-menu /
# "Open With" launcher), so it runs as the normal user and writes only into that
# user's home (see require_user). ``--add-pdf-signer`` on the root install
# re-invokes this as the user, like ``--apply-crash-fix``.
# ============================================================================

PDF_SIGNER_VENV = ORIG_HOME / '.venvs/pyhanko'
PDF_SIGNER_SCRIPT = ORIG_HOME / 'bin/cac-sign-pdf-gui.py'
PDF_SIGNER_DESKTOP = ORIG_HOME / '.local/share/applications/cac-sign-pdf.desktop'
PDF_SIGNER_PIP = ('pyHanko[pkcs11]', 'pypdf')
GET_PIP_URL = 'https://bootstrap.pypa.io/get-pip.py'

# The signer program, written verbatim to PDF_SIGNER_SCRIPT by ``pdf-signer``.
# (Raw string: backslash escapes and {braces} are literal here and become code
# only in the written-out file.)
_PDF_SIGNER_SRC = r'''#!/usr/bin/env python
"""GUI CAC PDF signer — signs an EXISTING signature block with the CAC (PKCS#11).

Run with a PDF path (e.g. from a file manager "Open With") or with no argument
(a file picker opens). It lists the document's signature fields, lets you pick an
empty one (handling forms with multiple blocks), prompts for the CAC PIN, and
signs INTO that field so the signature shows in the block. Unlike JSignPdf, it
targets the existing field rather than adding a separate/invisible signature.

Installed and updated by:  python3 cac-setup.py pdf-signer
"""
import os
import sys
import subprocess
from pathlib import Path
from shutil import which

# DoD PIV is standardized: the "Digital Signature" key is slot 9C -> OpenSC id 02,
# labelled "Certificate for Digital Signature" on every CAC. Only the token label
# (the cardholder's name) varies, so that is detected at runtime.
LIB = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
CERT_LABEL = "Certificate for Digital Signature"
KEY_ID = bytes.fromhex("02")
TITLE = "CAC PDF Signer"


def gui() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) and bool(which("zenity"))


def zen(*args) -> subprocess.CompletedProcess:
    return subprocess.run(["zenity", *args], capture_output=True, text=True)


def die(msg: str) -> None:
    if gui():
        zen("--error", "--width=440", f"--title={TITLE}", "--text", msg)
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def note(msg: str) -> None:
    if gui():
        zen("--info", "--width=480", f"--title={TITLE}", "--text", msg)
    else:
        print(msg)


def pick_pdf() -> str:
    if not gui():
        die("No PDF given. Usage: cac-sign-pdf-gui.py file.pdf")
    r = zen("--file-selection", "--title=Select a PDF to sign",
            "--file-filter=PDF files | *.pdf *.PDF")
    if r.returncode != 0:
        sys.exit(0)
    return r.stdout.strip()


def ordered_sig_field_names(path: str) -> list[str]:
    """Signature field names in visual reading order: page, top-to-bottom, left-to-right.

    Field *names* (e.g. "blank_10", "blank_1") often don't match where the blocks
    actually appear, so we sort by each widget's page and rectangle instead.
    """
    from pypdf import PdfReader
    from pypdf.generic import IndirectObject
    deref = lambda x: x.get_object() if isinstance(x, IndirectObject) else x
    items = []
    for pi, page in enumerate(PdfReader(path).pages):
        for a in (page.get("/Annots") or []):
            o = deref(a)
            parent = deref(o["/Parent"]) if "/Parent" in o else None
            if o.get("/FT") != "/Sig" and not (parent and parent.get("/FT") == "/Sig"):
                continue
            name = o.get("/T") or (parent.get("/T") if parent else None)
            rect = o.get("/Rect") or [0, 0, 0, 0]
            try:
                llx, _lly, _urx, ury = (float(v) for v in rect)
            except Exception:
                llx, ury = 0.0, 0.0
            if name is not None:
                items.append((pi, -ury, llx, str(name)))
    items.sort()
    seen, out = set(), []
    for *_, n in items:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def choose_field(empty: list[str]) -> str:
    if len(empty) == 1:
        return empty[0]
    if gui():
        rows: list[str] = []
        for i, f in enumerate(empty, 1):
            rows += [str(i), f]
        r = zen("--list", "--title=Choose signature block", "--height=360", "--width=470",
                "--text=Signature blocks in document order — pick the one to sign:",
                "--column=#", "--column=Signature block", "--print-column=2", *rows)
        if r.returncode != 0 or not r.stdout.strip():
            sys.exit(0)
        return r.stdout.strip().split("|")[0]
    for i, f in enumerate(empty, 1):
        print(f"  {i}. {f}")
    return empty[int(input("Block number to sign: ")) - 1]


def token_label() -> str | None:
    try:
        out = subprocess.run(["pkcs11-tool", "--list-slots"],
                             capture_output=True, text=True).stdout
    except FileNotFoundError:
        return None
    for line in out.splitlines():
        if "token label" in line:
            return line.split(":", 1)[1].strip()
    return None


def get_pin() -> str:
    if gui():
        r = zen("--password", "--title=CAC PIN")
        if r.returncode != 0:
            sys.exit(0)
        return r.stdout.strip()
    import getpass
    return getpass.getpass("CAC PIN: ")


def unique_out(infile: str) -> str:
    stem = Path(infile).stem
    if stem.endswith("_signed"):
        stem = stem[: -len("_signed")]
    base = Path(infile).with_name(stem + "_signed.pdf")
    out = base
    n = 2
    while out.exists():
        out = base.with_name(f"{stem}_signed_{n}.pdf")
        n += 1
    return str(out)


def main() -> None:
    infile = sys.argv[1] if len(sys.argv) > 1 else pick_pdf()
    infile = os.path.abspath(infile)
    if not infile.lower().endswith(".pdf") or not os.path.isfile(infile):
        die(f"Not a PDF file:\n{infile}")

    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.fields import enumerate_sig_fields
    with open(infile, "rb") as fh:
        fields = list(enumerate_sig_fields(PdfFileReader(fh)))
    empty = [t[0] for t in fields if t[1] is None]
    signed = [t[0] for t in fields if t[1] is not None]
    if not fields:
        die("This PDF has no signature blocks to sign.\n\n"
            "(This tool fills an existing signature field; this document has none.)")
    if not empty:
        die("Every signature block in this PDF is already signed:\n\n- " + "\n- ".join(signed))

    # Present blocks in document order (page, top-to-bottom), not by field name.
    rank = {n: i for i, n in enumerate(ordered_sig_field_names(infile))}
    empty.sort(key=lambda n: rank.get(n, len(rank)))

    field = choose_field(empty)

    label = token_label()
    if not label:
        die("No CAC detected. Insert your CAC and try again.")
    pin = get_pin()
    if not pin:
        die("No PIN entered.")

    outfile = unique_out(infile)

    from pyhanko.sign import pkcs11, signers
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    try:
        session = pkcs11.open_pkcs11_session(LIB, token_label=label, user_pin=pin)
    except Exception as e:
        die("Could not log in to the CAC. Check your PIN and try again — but note the "
            f"card locks after 3 wrong attempts.\n\nDetails: {e}")
    try:
        signer = pkcs11.PKCS11Signer(session, cert_label=CERT_LABEL, key_id=KEY_ID)
        meta = signers.PdfSignatureMetadata(field_name=field)
        with open(outfile, "wb") as outf:
            signers.sign_pdf(IncrementalPdfFileWriter(open(infile, "rb")), meta,
                             signer=signer, existing_fields_only=True, output=outf)
    except Exception as e:
        die(f"Signing failed:\n\n{e}")
    finally:
        try:
            session.close()
        except Exception:
            pass

    remaining = [f for f in empty if f != field]
    extra = ("\n\nRemaining unsigned blocks: " + ", ".join(remaining) +
             "\nRun this again on the signed file to sign another.") if remaining else ""
    note(f'Signed the “{field}” block with your CAC.\n\nSaved as:\n{outfile}{extra}')


if __name__ == "__main__":
    main()
'''


def _ensure_pyhanko_venv() -> None:
    """Create PDF_SIGNER_VENV (if absent) and install pyHanko + pypdf into it.

    Tries the stdlib ``venv`` first; if that lacks pip/ensurepip (Ubuntu ships it
    separately as python3-venv), falls back to a no-sudo ``--without-pip`` venv
    bootstrapped with the official get-pip.py. Idempotent: skips the work when the
    packages already import.
    """
    py = PDF_SIGNER_VENV / 'bin' / 'python'
    if py.exists() and subprocess.run(
            [str(py), '-c', 'import pyhanko, pypdf'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        print('  pyHanko venv already present.')
        return
    if not py.exists():
        PDF_SIGNER_VENV.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(['python3', '-m', 'venv', str(PDF_SIGNER_VENV)],
                       capture_output=True, text=True)
        if not (PDF_SIGNER_VENV / 'bin' / 'pip').exists():
            # ensurepip/python3-venv missing: a bare venv + get-pip works without sudo.
            shutil.rmtree(PDF_SIGNER_VENV, ignore_errors=True)
            subprocess.run(['python3', '-m', 'venv', '--without-pip', str(PDF_SIGNER_VENV)],
                           check=True)
            getpip = Path('/tmp/get-pip.py')
            urllib.request.urlretrieve(GET_PIP_URL, getpip)
            subprocess.run([str(py), str(getpip)], check=True)
    print('  installing pyHanko + pypdf (first run downloads a few MB)...')
    subprocess.run([str(py), '-m', 'pip', 'install', '-q', '--upgrade', 'pip', *PDF_SIGNER_PIP],
                   check=True)


def _write_pdf_signer_launcher() -> None:
    """Write the app-menu / 'Open With' .desktop entry for the signer."""
    exec_line = f"{PDF_SIGNER_VENV / 'bin' / 'python'} {PDF_SIGNER_SCRIPT} %f"
    PDF_SIGNER_DESKTOP.parent.mkdir(parents=True, exist_ok=True)
    PDF_SIGNER_DESKTOP.write_text(
        "[Desktop Entry]\n"
        "Name=Sign PDF with CAC\n"
        "Comment=Sign an existing signature block in a PDF using your CAC\n"
        f"Exec={exec_line}\n"
        "Icon=application-pdf\n"
        "Terminal=false\nType=Application\nCategories=Office;Utility;\n"
        "MimeType=application/pdf;\nStartupNotify=true\n"
    )
    subprocess.run(
        f'update-desktop-database {shlex.quote(str(PDF_SIGNER_DESKTOP.parent))} 2>/dev/null',
        shell=True)


def cmd_pdf_signer(argv: list[str]) -> None:
    """Install (or --revert) the GUI CAC PDF signer for the current user."""
    require_user('pdf-signer')
    if '--revert' in argv:
        removed = []
        for p in (PDF_SIGNER_DESKTOP, PDF_SIGNER_SCRIPT):
            if p.exists():
                p.unlink()
                removed.append(str(p))
        if PDF_SIGNER_VENV.exists():
            shutil.rmtree(PDF_SIGNER_VENV, ignore_errors=True)
            removed.append(str(PDF_SIGNER_VENV))
        subprocess.run(
            f'update-desktop-database {shlex.quote(str(PDF_SIGNER_DESKTOP.parent))} 2>/dev/null',
            shell=True)
        for r in removed:
            print(f'  removed {r}')
        print('PDF signer removed.' if removed else 'PDF signer was not installed.')
        return

    print('Setting up the CAC PDF signer...')
    _ensure_pyhanko_venv()
    PDF_SIGNER_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
    PDF_SIGNER_SCRIPT.write_text(_PDF_SIGNER_SRC)
    PDF_SIGNER_SCRIPT.chmod(0o755)
    _write_pdf_signer_launcher()
    print('PDF signer installed. Launch "Sign PDF with CAC" from your app menu, or '
          'right-click a PDF -> Open With.\n'
          f'  signer:   {PDF_SIGNER_SCRIPT}\n  launcher: {PDF_SIGNER_DESKTOP}')


def install_pdf_signer() -> None:
    """Set up the PDF signer as ORIG_USER (used by --add-pdf-signer on the root install)."""
    if DRY_RUN:
        log(f'[DRY RUN] Would install the CAC PDF signer (venv + script + launcher) as {ORIG_USER}.')
        return
    script = str(Path(__file__).resolve())
    log(f'Setting up the CAC PDF signer as {ORIG_USER}...')
    sudo_user('python3', script, 'pdf-signer')
    log('CAC PDF signer ready ("Sign PDF with CAC" in the app menu).')


def remove_pdf_signer() -> None:
    """Remove the PDF signer as ORIG_USER (used by --remove-pdf-signer)."""
    if DRY_RUN:
        log(f'[DRY RUN] Would remove the CAC PDF signer as {ORIG_USER}.')
        return
    script = str(Path(__file__).resolve())
    log(f'Removing the CAC PDF signer as {ORIG_USER}...')
    sudo_user('python3', script, 'pdf-signer', '--revert')


# ============================================================================
# Orchestration
# ============================================================================

def _select_databases(args: argparse.Namespace) -> list[str]:
    """Discover NSS databases and apply the --only/--exclude browser filters."""
    db_roots = browser_databases()
    if not db_roots:
        raise SystemExit('No supported browser or NSS database locations found.')

    only = [s.strip().lower() for s in (args.only_browsers or '').split(',') if s.strip()]
    exclude = [s.strip().lower() for s in (args.exclude_browsers or '').split(',') if s.strip()]
    if only:
        db_roots = [d for d in db_roots if any(o in d.lower() for o in only)]
    if exclude:
        db_roots = [d for d in db_roots if not any(e in d.lower() for e in exclude)]

    if not db_roots:
        raise SystemExit('No NSS databases matched the filters provided.')
    return db_roots


def _resolve_workers(requested: int, db_count: int) -> int:
    """Pick the worker count: explicit request if given, else auto (capped at 4)."""
    if requested and requested > 0:
        return min(requested, db_count)
    return min(4, db_count)


def apply_crash_fix() -> None:
    """Apply the memlock crash fix to every Chromium-family browser (incl. Chrome).

    Runs the user-level ``crash-fix`` subcommand as ORIG_USER so the
    generated desktop files are owned by that user; calling the logic inline from
    this root process would create root-owned launchers the user could not edit.
    """
    if DRY_RUN:
        log(f'[DRY RUN] Would prlimit-wrap every Chromium-family browser (as {ORIG_USER}).')
        return
    script = str(Path(__file__).resolve())
    log(f'Applying browser crash fix as {ORIG_USER}...')
    sudo_user('python3', script, 'crash-fix')
    log('Browser crash fix applied. Fully relaunch each browser for it to take effect.')


def revert_crash_fix() -> None:
    """Undo the crash fix for every Chromium-family browser, as ORIG_USER."""
    if DRY_RUN:
        log(f'[DRY RUN] Would remove the crash-fix overrides for all browsers (as {ORIG_USER}).')
        return
    script = str(Path(__file__).resolve())
    log(f'Reverting browser crash fix as {ORIG_USER}...')
    sudo_user('python3', script, 'crash-fix', '--revert')
    log('Browser crash fix reverted.')


def main() -> None:
    """Entry point: dispatch a user-level subcommand, else run the CAC cert install."""
    # ``crash-fix`` is the canonical name (matching the --apply-crash-fix /
    # --revert-crash-fix flags); the plural/singular spellings are kept as
    # aliases so older invocations and an easy typo still work.
    subcommands = {
        'crash-fix': cmd_browsers_crash_fix,
        'browsers-crash-fix': cmd_browsers_crash_fix,
        'browser-crash-fix': cmd_browsers_crash_fix,
        'pdf-signer': cmd_pdf_signer,
        'trace-locks': cmd_trace_locks,
    }
    if len(sys.argv) > 1 and sys.argv[1] in subcommands:
        subcommands[sys.argv[1]](sys.argv[2:])
        return

    args = parse_args()
    global DRY_RUN, VERBOSE
    DRY_RUN = args.dry_run
    VERBOSE = args.verbose

    # Reverting the crash fix is a standalone action: do it (as the invoking user)
    # and exit without touching certs.
    if args.revert_crash_fix:
        if not DRY_RUN:
            require_root()
        revert_crash_fix()
        return

    # Removing the PDF signer is likewise standalone: do it and exit.
    if args.remove_pdf_signer:
        if not DRY_RUN:
            require_root()
        remove_pdf_signer()
        return

    if not DRY_RUN:
        require_root()

    install_packages()
    ensure_pcscd()  # the smartcard daemon must be running to read the CAC
    connect_snap_firefox_pcscd()  # let a snap-confined Firefox reach pcscd
    download_certs()
    init_firefox_profile()
    init_chrome_profile()
    ensure_pki_nssdb()  # create the shared ~/.pki/nssdb if a fresh machine lacks it

    db_roots = _select_databases(args)
    max_workers = _resolve_workers(args.max_workers, len(db_roots))

    # NSS databases are independent, so update them in parallel.
    results: list[DBResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(import_certs, db): db for db in db_roots}
        for fut in concurrent.futures.as_completed(futures):
            db = futures[fut]
            try:
                res = fut.result()
                if res:
                    results.append(res)
            except Exception as e:
                log(f'Error updating {db}: {e}')

    total_imported = sum(r.imported for r in results)
    total_time = sum(r.duration for r in results)
    log(f'Summary: imported {total_imported} new cert(s) across {len(results)} DB(s) '
        f'in {total_time:.2f}s total (sum of DB times).')

    # In verbose mode, report the resulting certificate count per database.
    if VERBOSE:
        for db in db_roots:
            verify_certs(db)

    # Restart Firefox if any active default profile was one of the updated databases.
    default_profiles = firefox_default_profiles()
    if any(str(p) in r.db for p in default_profiles for r in results):
        restart_firefox()

    # The launcher is optional: certs are imported into the existing default
    # profile, so plain Firefox already works. Only create it when asked.
    if default_profiles and args.create_launcher:
        create_launcher(default_profiles[0])

    # Optional system-policy step: keep the CAC out of the OS login screen.
    if args.disable_login_smartcard:
        disable_login_smartcard()

    # Optional: also apply the browser memory-lock crash fix (Chrome launcher +
    # other Chromium-family browsers), run as the invoking user.
    if args.apply_crash_fix:
        apply_crash_fix()

    # Optional: also set up the GUI CAC PDF signer, run as the invoking user.
    if args.add_pdf_signer:
        install_pdf_signer()

    log('Done.')


if __name__ == '__main__':
    main()
