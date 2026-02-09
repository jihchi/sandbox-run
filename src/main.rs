use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() {
    let prog = env::args_os()
        .next()
        .and_then(|a| {
            Path::new(&a)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "sandbox-run".to_string());

    if let Err(e) = run() {
        eprintln!("{prog}: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<OsString> = env::args_os().collect();
    let argv0 = &args[0];
    let (uid, gid, ppid) = read_proc_self_status()?;
    let cwd = env::current_dir()?;

    if which("bwrap").is_none() {
        eprintln!("Error: Missing bwrap (apt install bubblewrap?)");
        std::process::exit(127);
    }

    let argv0_path = Path::new(argv0);
    let is_symlink = fs::symlink_metadata(argv0_path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);

    // Determine the target binary and user arguments based on invocation mode:
    //
    // Symlink mode: argv0 is a symlink (e.g., `python -> sandbox-run`).
    //   The actual binary is found by searching PATH for an executable with the
    //   same basename, skipping any candidate that resolves to sandbox-run itself
    //   to avoid infinite recursion (e.g., a symlink `sandbox-run -> sandbox-run`).
    //   All arguments after argv0 are forwarded to the resolved binary.
    //
    // Direct mode: invoked directly as `sandbox-run <cmd> [args...]`.
    //   The first argument is the command to run, resolved via PATH. The same
    //   self-avoidance applies: `sandbox-run sandbox-run ...` resolves to the
    //   real binary rather than recursing into itself.
    let (bin, user_args): (PathBuf, Vec<OsString>) = if is_symlink {
        let base = argv0_path.file_name().unwrap_or(argv0.as_ref());
        let resolved = resolve_symlink_bin(argv0, base)?;
        (resolved, args[1..].to_vec())
    } else {
        if args.len() < 2 {
            let name = argv0_path
                .file_name()
                .unwrap_or(OsStr::new("sandbox-run"))
                .to_string_lossy();
            eprintln!("Usage: {name} ARG...");
            std::process::exit(1);
        }
        let cmd = &args[1];
        let resolved = resolve_command(cmd)?;
        (resolved, args[2..].to_vec())
    };

    let formatted_cmdline = format_args_display(&bin, &user_args, &cwd);

    let prev_bwrap_args = env::var("BWRAP_ARGS").unwrap_or_default();

    let dotenv = load_dotenv(&cwd)?;

    let env_get = |key: &str| -> String {
        dotenv
            .as_ref()
            .and_then(|m| m.get(OsStr::new(key)))
            .map(|v| v.to_string_lossy().into_owned())
            .unwrap_or_else(|| env::var(key).unwrap_or_default())
    };

    let default_ro_paths: Vec<&str> = vec![
        "/etc/alternatives",
        "/etc/resolv.conf",
        "/etc/ssl",
        "/etc/hosts",
        "/etc/pki",
        "/etc/pkcs11",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf.d",
        "/etc/localtime",
        "/etc/os-release",
        "/etc/timezone",
        "/lib",
        "/lib64",
        "/run/dbus/system_bus_socket",
        "/usr",
    ];
    let rw_paths: Vec<&str> = vec!["/etc/ld.so.conf.d"];

    let sandbox_ro_bind = env_get("SANDBOX_RO_BIND");
    let extra_ro_tokens = parse_sandbox_ro_bind(&sandbox_ro_bind);

    let mut ro_bind_paths: Vec<PathBuf> = Vec::new();
    for token in &extra_ro_tokens {
        for p in expand_glob(token) {
            ro_bind_paths.push(p);
        }
    }
    for p in &default_ro_paths {
        ro_bind_paths.push(PathBuf::from(p));
    }

    let mut rw_bind_paths: Vec<PathBuf> = Vec::new();
    for p in &rw_paths {
        rw_bind_paths.push(PathBuf::from(p));
    }

    let home = cwd.join(".sandbox-home");
    fs::create_dir_all(home.join("tmp"))?;

    let new_bwrap_args_str = env_get("BWRAP_ARGS");
    let new_bwrap_tokens = split_args_by_lf(&new_bwrap_args_str);
    let prev_bwrap_tokens = split_args_by_lf(&prev_bwrap_args);

    let env_setenv_args = build_env_pass_through(ppid, &dotenv)?;

    let passwd_text = run_getent_passwd(uid);
    let group_text = run_getent_group(gid);

    let passwd_file = home.join("tmp").join(".passwd");
    let group_file = home.join("tmp").join(".group");
    fs::write(&passwd_file, &passwd_text)?;
    fs::write(&group_file, &group_text)?;

    let verbose = {
        let v = env_get("VERBOSE");
        if v.is_empty() { env_get("verbose") } else { v }
    };
    let verbose = !verbose.is_empty();

    eprintln!("sandbox-run: exec bwrap [...] {formatted_cmdline}");

    let mut bwrap_argv: Vec<OsString> = Vec::new();

    bwrap_argv.extend_from_slice(&oss(&[
        "--tmpfs", "/tmp", "--tmpfs", "/run", "--proc", "/proc", "--dev", "/dev", "--symlink",
        "/run", "/var/run", "--symlink", "/tmp", "/var/tmp", "--symlink", "/usr/bin", "/bin",
        "--symlink", "/usr/bin", "/sbin", "--dev-bind-try", "/dev/fuse", "/dev/fuse",
    ]));

    bwrap_argv.extend_from_slice(&oss(&["--ro-bind"]));
    bwrap_argv.push(bin.as_os_str().to_owned());
    bwrap_argv.push(bin.as_os_str().to_owned());

    for path in &ro_bind_paths {
        if path.exists() {
            bwrap_argv.push(OsString::from("--ro-bind-try"));
            bwrap_argv.push(path.as_os_str().to_owned());
            bwrap_argv.push(path.as_os_str().to_owned());
        }
    }
    for path in &rw_bind_paths {
        if path.exists() {
            bwrap_argv.push(OsString::from("--bind-try"));
            bwrap_argv.push(path.as_os_str().to_owned());
            bwrap_argv.push(path.as_os_str().to_owned());
        }
    }

    bwrap_argv.extend_from_slice(&oss(&["--bind"]));
    bwrap_argv.push(cwd.as_os_str().to_owned());
    bwrap_argv.push(cwd.as_os_str().to_owned());

    bwrap_argv.extend_from_slice(&oss(&["--chdir"]));
    bwrap_argv.push(cwd.as_os_str().to_owned());

    bwrap_argv.extend_from_slice(&oss(&[
        "--clearenv",
        "--unshare-all",
        "--share-net",
        "--new-session",
        "--die-with-parent",
    ]));

    let run_user = format!("/run/user/{uid}");
    bwrap_argv.extend_from_slice(&oss(&["--dir"]));
    bwrap_argv.push(OsString::from(&run_user));
    bwrap_argv.extend_from_slice(&oss(&["--setenv", "XDG_RUNTIME_DIR"]));
    bwrap_argv.push(OsString::from(&run_user));
    bwrap_argv.extend_from_slice(&oss(&["--setenv", "PATH", "/usr/bin"]));
    bwrap_argv.extend_from_slice(&oss(&["--setenv", "PS1", "\\u @ \\h \\$ "]));
    bwrap_argv.extend_from_slice(&oss(&["--setenv", "HOME"]));
    bwrap_argv.push(home.as_os_str().to_owned());
    bwrap_argv.extend_from_slice(&oss(&["--setenv", "USER", "user"]));
    bwrap_argv.extend_from_slice(&oss(&["--setenv", "TMPDIR"]));
    bwrap_argv.push(OsString::from(home.join("tmp")));

    bwrap_argv.extend_from_slice(&oss(&["--ro-bind"]));
    bwrap_argv.push(passwd_file.as_os_str().to_owned());
    bwrap_argv.push(OsString::from("/etc/passwd"));
    bwrap_argv.extend_from_slice(&oss(&["--ro-bind"]));
    bwrap_argv.push(group_file.as_os_str().to_owned());
    bwrap_argv.push(OsString::from("/etc/group"));

    for a in &env_setenv_args {
        bwrap_argv.push(a.clone());
    }

    for t in &new_bwrap_tokens {
        if !t.is_empty() {
            bwrap_argv.push(OsString::from(t));
        }
    }
    for t in &prev_bwrap_tokens {
        if !t.is_empty() {
            bwrap_argv.push(OsString::from(t));
        }
    }

    bwrap_argv.push(bin.as_os_str().to_owned());
    for a in &user_args {
        bwrap_argv.push(a.clone());
    }

    if verbose {
        let display: Vec<String> = bwrap_argv
            .iter()
            .map(|a| {
                let s = a.to_string_lossy();
                if s.contains(' ') {
                    format!("'{s}'")
                } else {
                    s.into_owned()
                }
            })
            .collect();
        eprintln!("+ bwrap {}", display.join(" "));
    }

    let status = Command::new("bwrap").args(&bwrap_argv).status()?;
    std::process::exit(status.code().unwrap_or(1));
}

fn oss(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn read_proc_self_status() -> Result<(u32, u32, u32), Box<dyn std::error::Error>> {
    let content = fs::read_to_string("/proc/self/status")?;
    let mut uid: Option<u32> = None;
    let mut gid: Option<u32> = None;
    let mut ppid: Option<u32> = None;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            gid = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        } else if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        }
    }

    Ok((
        uid.ok_or("failed to read uid from /proc/self/status")?,
        gid.ok_or("failed to read gid from /proc/self/status")?,
        ppid.ok_or("failed to read ppid from /proc/self/status")?,
    ))
}

fn which(name: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH").unwrap_or_default();
    for dir in env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() && is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(meta) => meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

fn resolve_symlink_bin(argv0: &OsStr, base: &OsStr) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path_var = env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string());
    let self_real = fs::canonicalize(argv0).ok();

    for dir in path_var.split(':') {
        let candidate = PathBuf::from(format!("{dir}/{}", base.to_string_lossy()));
        if !is_executable(&candidate) {
            continue;
        }
        let candidate_real = fs::canonicalize(&candidate).ok();
        if candidate_real.is_some() && candidate_real == self_real {
            continue;
        }
        return Ok(candidate);
    }
    Ok(PathBuf::from(argv0))
}

fn resolve_command(cmd: &OsStr) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let cmd_bytes = cmd.as_bytes();
    if cmd_bytes.contains(&b'/') {
        return Ok(PathBuf::from(cmd));
    }
    let path_var = env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string());
    for dir in path_var.split(':') {
        let d = if dir.is_empty() { "." } else { dir };
        let candidate = PathBuf::from(d).join(cmd);
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }
    Err(format!("{}: command not found", cmd.to_string_lossy()).into())
}

fn format_args_display(bin: &Path, user_args: &[OsString], cwd: &Path) -> String {
    let cwd_str = cwd.to_string_lossy();
    let cwd_prefix = format!("{cwd_str}/");
    let cwd_base = cwd
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut parts = Vec::new();
    let mut all_args = vec![OsString::from(bin.as_os_str())];
    all_args.extend_from_slice(user_args);

    for arg in &all_args {
        let s = arg.to_string_lossy();
        if s.starts_with(&cwd_prefix) {
            let relative = &s[cwd_prefix.len()..];
            parts.push(format!("{cwd_base}/{relative}"));
        } else if s.contains(' ') {
            parts.push(format!("'{s}'"));
        } else {
            parts.push(s.into_owned());
        }
    }
    let mut result = parts.join(" ");
    result.push(' ');
    result
}

fn split_args_by_lf(s: &str) -> Vec<String> {
    if s.contains('\n') {
        s.split('\n')
            .map(|t| t.to_string())
            .filter(|t| !t.is_empty())
            .collect()
    } else {
        s.split(' ')
            .map(|t| t.to_string())
            .filter(|t| !t.is_empty())
            .collect()
    }
}

fn parse_sandbox_ro_bind(val: &str) -> Vec<String> {
    let tokens = split_args_by_lf(val);
    let mut result = Vec::new();
    for tok in tokens {
        for sub in tok.split(',') {
            if !sub.is_empty() {
                result.push(sub.to_string());
            }
        }
    }
    result
}

fn expand_glob(pattern: &str) -> Vec<PathBuf> {
    match glob::glob(pattern) {
        Ok(paths) => {
            let mut results: Vec<PathBuf> = paths.filter_map(|p| p.ok()).collect();
            if results.is_empty() {
                vec![PathBuf::from(pattern)]
            } else {
                results.sort();
                results
            }
        }
        Err(_) => vec![PathBuf::from(pattern)],
    }
}

fn load_dotenv(cwd: &Path) -> Result<Option<HashMap<OsString, OsString>>, Box<dyn std::error::Error>> {
    let dotenv_path = cwd.join(".env");
    if !dotenv_path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&dotenv_path)?;
    let mut keys: Vec<String> = Vec::new();
    for line in content.lines() {
        if let Some(eq_pos) = line.find('=') {
            let key = &line[..eq_pos];
            if !key.is_empty() && key.chars().all(|c| c.is_alphanumeric() || c == '_') {
                keys.push(key.to_string());
            }
        }
    }

    if keys.is_empty() {
        return Ok(None);
    }

    let export_list = keys.join(" ");
    let script = format!(". \"$1\"; export {export_list}; env -0");

    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(&script)
        .arg("sh")
        .arg(&dotenv_path)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()?;

    if !output.status.success() {
        return Err(format!("failed to source .env (exit {})", output.status).into());
    }

    Ok(Some(parse_null_separated_env(&output.stdout)))
}

fn parse_null_separated_env(data: &[u8]) -> HashMap<OsString, OsString> {
    let mut map = HashMap::new();
    for entry in data.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        let s = OsStr::from_bytes(entry).as_bytes();
        if let Some(eq) = s.iter().position(|&b| b == b'=') {
            let key = OsStr::from_bytes(&s[..eq]).to_owned();
            let val = OsStr::from_bytes(&s[eq + 1..]).to_owned();
            map.insert(key, val);
        }
    }
    map
}

fn read_proc_environ(pid: u32) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let path = format!("/proc/{pid}/environ");
    let data = fs::read(&path)?;
    let mut keys = HashSet::new();
    for entry in data.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        if let Some(eq) = entry.iter().position(|&b| b == b'=') {
            let key = String::from_utf8_lossy(&entry[..eq]).into_owned();
            keys.insert(key);
        }
    }
    Ok(keys)
}

fn build_env_pass_through(
    ppid: u32,
    dotenv: &Option<HashMap<OsString, OsString>>,
) -> Result<Vec<OsString>, Box<dyn std::error::Error>> {
    let parent_keys = read_proc_environ(ppid).unwrap_or_default();

    let whitelist_exact: HashSet<&str> = [
        "USER", "LOGNAME", "UID", "PATH", "TERM", "HOSTNAME", "LANGUAGE", "LANG", "TZ",
        "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "CC", "CFLAGS", "CXXFLAGS",
        "CPPFLAGS", "LDFLAGS", "LDLIBS", "MAKEFLAGS",
    ]
    .iter()
    .copied()
    .collect();

    let blacklist_exact: HashSet<&str> = ["_", "LS_COLORS", "PS1", "BWRAP_ARGS", "SANDBOX_RO_BIND"]
        .iter()
        .copied()
        .collect();

    let current_env: Vec<(String, OsString)> = match dotenv {
        Some(map) => map
            .iter()
            .map(|(k, v)| (k.to_string_lossy().into_owned(), v.clone()))
            .collect(),
        None => read_current_env_ordered()?,
    };

    let current_keys: HashSet<String> = current_env.iter().map(|(k, _)| k.clone()).collect();
    let exclusive_keys: HashSet<&str> = current_keys
        .iter()
        .filter(|k| !parent_keys.contains(k.as_str()))
        .map(|k| k.as_str())
        .collect();

    let mut filtered: Vec<(&str, &OsStr)> = Vec::new();
    for (key, val) in &current_env {
        let name = key.as_str();
        let in_whitelist = whitelist_exact.contains(name) || name.starts_with("LC_");
        let is_exclusive = exclusive_keys.contains(name);

        if !in_whitelist && !is_exclusive {
            continue;
        }

        if blacklist_exact.contains(name) || name.starts_with('_') {
            continue;
        }

        filtered.push((name, val.as_os_str()));
    }

    let mut result: Vec<OsString> = Vec::new();
    for (name, val) in filtered.iter().rev() {
        result.push(OsString::from("--setenv"));
        result.push(OsString::from(name));
        result.push((*val).to_owned());
    }
    Ok(result)
}

fn read_current_env_ordered() -> Result<Vec<(String, OsString)>, Box<dyn std::error::Error>> {
    let data = fs::read("/proc/self/environ")?;
    let mut entries = Vec::new();
    let mut seen = HashSet::new();

    for entry in data.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        if let Some(eq) = entry.iter().position(|&b| b == b'=') {
            let key = String::from_utf8_lossy(&entry[..eq]).into_owned();
            if seen.insert(key.clone()) {
                let val = OsStr::from_bytes(&entry[eq + 1..]).to_owned();
                entries.push((key, val));
            }
        }
    }

    for (key, val) in env::vars_os() {
        let key_str = key.to_string_lossy().into_owned();
        if seen.insert(key_str.clone()) {
            entries.push((key_str, val));
        }
    }

    Ok(entries)
}

fn run_getent_passwd(uid: u32) -> String {
    let output = Command::new("getent")
        .arg("passwd")
        .arg(uid.to_string())
        .arg("65534")
        .output();
    match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(_) => String::new(),
    }
}

fn run_getent_group(gid: u32) -> String {
    let output = Command::new("getent")
        .arg("group")
        .arg(gid.to_string())
        .args([
            "65534", "adm", "sudo", "audio", "dip", "video", "plugdev", "staff", "users",
            "netdev", "scanner", "bluetooth", "lpadmin",
        ])
        .output();
    match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(_) => String::new(),
    }
}
