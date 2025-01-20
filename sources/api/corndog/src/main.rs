/*!
corndog is a delicious way to get at the meat inside the kernels.
It sets kernel-related settings, for example:
* sysctl values, based on key/value pairs in `settings.kernel.sysctl`
* lockdown mode, based on the value of `settings.kernel.lockdown`

corndog also provides a settings generator for hugepages, subcommand "generate-hugepages-setting".
*/

use bottlerocket_modeled_types::{Lockdown, SysctlKey};
use log::{debug, info, trace, warn};
use serde::{Deserialize, Serialize};
use simplelog::{Config as LogConfig, LevelFilter, SimpleLogger};
use snafu::ResultExt;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::string::String;
use std::{env, process};
use tempfile::NamedTempFile;

const LOCKDOWN_PATH: &str = "/sys/kernel/security/lockdown";
const DEFAULT_CONFIG_PATH: &str = "/etc/corndog.toml";
const SYSCTL_CONFIG_DIR: &str = "/etc/sysctl.d";
const SYSCTL_CONFIG_FILENAME: &str = "95-corndog.conf";
const SYSTEMD_SYSCTL_BIN: &str = "/usr/lib/systemd/systemd-sysctl";
const NR_HUGEPAGES_PATH_SYSCTL: &str = "/proc/sys/vm/nr_hugepages";
/// Number of hugepages we will assign per core.
/// See [`compute_hugepages_for_efa`] for more detail on the computation consideration.
const HUGEPAGES_2MB_PER_CORE: u64 = 110;

/// Store the args we receive on the command line.
struct Args {
    subcommand: String,
    log_level: LevelFilter,
    config_path: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct KernelSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lockdown: Option<Lockdown>,
    // Values are almost always a single line and often just an integer... but not always.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sysctl: Option<HashMap<SysctlKey, String>>,
}

/// Trait for executing system commands
trait CommandExecutor {
    fn execute(&self, cmd: &str) -> std::io::Result<std::process::ExitStatus>;
}

/// Real command executor that runs actual system commands
struct SystemCommandExecutor;

impl CommandExecutor for SystemCommandExecutor {
    fn execute(&self, cmd: &str) -> std::io::Result<std::process::ExitStatus> {
        process::Command::new(cmd).status()
    }
}

/// Main entry point.
fn run() -> Result<()> {
    let args = parse_args(env::args());

    // SimpleLogger will send errors to stderr and anything less to stdout.
    SimpleLogger::init(args.log_level, LogConfig::default()).context(error::LoggerSnafu)?;

    // If the user has kernel settings, apply them.
    match args.subcommand.as_ref() {
        "sysctl" => {
            let kernel = get_kernel_settings(args.config_path)?;
            if let Some(sysctls) = kernel.sysctl {
                debug!("Applying sysctls: {:#?}", sysctls);
                set_sysctls(sysctls)?;
            }
        }
        "lockdown" => {
            let kernel = get_kernel_settings(args.config_path)?;
            if let Some(lockdown) = kernel.lockdown {
                debug!("Setting lockdown: {:#?}", lockdown);
                set_lockdown(&lockdown)?;
            }
        }
        "generate-hugepages-setting" => {
            let hugepages_setting = generate_hugepages_setting()?;
            // We will only fail if we cannot serialize the output to JSON string.
            // sundog expects JSON-serialized output so that many types can be represented, allowing the
            // API model to use more accurate types.
            let output =
                serde_json::to_string(&hugepages_setting).context(error::SerializeJsonSnafu)?;
            println!("{}", output);
        }
        _ => usage_msg(format!("Unknown subcommand '{}'", args.subcommand)), // should be unreachable
    }

    Ok(())
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// Retrieve the current model from the API.
fn get_kernel_settings<P>(config_path: P) -> Result<KernelSettings>
where
    P: AsRef<Path>,
{
    let config_str =
        fs::read_to_string(config_path.as_ref()).context(error::ReadConfigFileSnafu)?;
    toml::from_str(config_str.as_str()).context(error::DeserializationSnafu)
}

/// Generate sysctl config file content from key-value pairs
fn generate_sysctl_config<K>(sysctls: &HashMap<K, String>) -> String
where
    K: AsRef<str>,
{
    let mut config_content = String::new();
    for (key, value) in sysctls {
        let key = key.as_ref();
        config_content.push_str(&format!("{} = {}\n", key, value.trim()));
    }
    config_content
}

/// Write sysctl config to a file, using a temporary file and atomic rename
fn persist_sysctl_config(
    config_content: &str,
    config_dir: &str,
    config_filename: &str,
) -> Result<PathBuf> {
    // Create a temporary file in the sysctl config directory
    let tempfile = NamedTempFile::new_in(config_dir).context(error::CreateTempFileSnafu {
        path: PathBuf::from(config_dir),
    })?;

    // Write the config to the temporary file
    fs::write(tempfile.path(), config_content).context(error::WriteTempFileSnafu)?;

    // Construct the final path and atomically move the temporary file to it
    let config_path = Path::new(config_dir).join(config_filename);
    tempfile.persist(&config_path).context(error::PersistTempFileSnafu {
        path: config_path.clone(),
    })?;

    Ok(config_path)
}

/// Apply sysctl settings using the given systemd-sysctl binary
fn apply_sysctl_config(systemd_sysctl_bin: &str, executor: &dyn CommandExecutor) -> Result<()> {
    let status = executor
        .execute(systemd_sysctl_bin)
        .context(error::RunSystemdSysctlSnafu)?;

    if !status.success() {
        error::SystemdSysctlFailedSnafu { status }.fail()?;
    }

    debug!("Successfully applied sysctl settings");
    Ok(())
}

/// Applies the requested sysctls to the system by writing them to a config file and using systemd-sysctl.
/// The keys are used to generate the appropriate path, and the value its contents.
fn set_sysctls<K>(sysctls: HashMap<K, String>) -> Result<()>
where
    K: AsRef<str>,
{
    let config_content = generate_sysctl_config(&sysctls);
    persist_sysctl_config(&config_content, SYSCTL_CONFIG_DIR, SYSCTL_CONFIG_FILENAME)?;
    apply_sysctl_config(SYSTEMD_SYSCTL_BIN, &SystemCommandExecutor)
}

/// Generate the hugepages setting for defaults.
fn generate_hugepages_setting() -> Result<String> {
    // Check if customer has directly written to the nr_hugepage file.
    let mut hugepages = fs::read_to_string(NR_HUGEPAGES_PATH_SYSCTL)
        .map(check_for_existing_hugepages)
        .unwrap_or("0".to_string());

    // Check for EFA and compute if necessary, only when hugepages is "0".
    if &hugepages == "0" && pciclient::is_efa_attached().unwrap_or(false) {
        // We will use [`num_cpus`] to get the number of cores for the compute.
        hugepages = compute_hugepages_for_efa(num_cpus::get());
    }
    Ok(hugepages)
}

// Check if customer has directly written to the nr_hugepage file.
//
// This would be a rare case to hit, as customer would normally modify the hugepages value
// via settings API. (It could happen with a custom variant if hugepages
// are set via a sysctl.d drop-in, for example.)
//
// We expect the existing_hugepages_value to be valid numeric digits. Otherwise, we will
// use "0" as default.
fn check_for_existing_hugepages(existing_hugepages_value: String) -> String {
    match existing_hugepages_value.trim().parse::<u64>() {
        Ok(value) => {
            return value.to_string();
        }
        Err(err) => {
            warn!(
                "Failed to parse the existing hugepage value, using 0 as default. Error: {}",
                err
            );
        }
    }
    "0".to_string()
}

/// Computation:
/// - We need to allocate 110MB memory for each libfabric endpoint.
/// - For optimal setup, Open MPI will open 2 libfabric endpoints each core.
/// - The total number of hugepages will be set as (110MB * 2) * number_of_cores / hugepage_size
/// - We will allocate default hugepage_size = 2MB.
/// - The number of hugepage per core would be 110MB * 2 / 2MB = 110.
fn compute_hugepages_for_efa(num_cores: usize) -> String {
    let number_of_hugepages = num_cores as u64 * HUGEPAGES_2MB_PER_CORE;
    number_of_hugepages.to_string()
}

/// Sets the requested lockdown mode in the kernel.
///
/// The Linux kernel won't allow lowering the lockdown setting, but we want to allow users to
/// change the Bottlerocket setting and reboot for it to take effect.  Changing the Bottlerocket
/// setting means this code will run to write it out, but it wouldn't be able to convince the
/// kernel.  So, we just warn the user rather than trying to write and causing a failure that could
/// prevent the rest of a settings-changing transaction from going through.  We'll run again after
/// reboot to set lockdown as it was requested.
fn set_lockdown(lockdown: &str) -> Result<()> {
    let current_raw = fs::read_to_string(LOCKDOWN_PATH).unwrap_or_else(|_| "unknown".to_string());
    let current = parse_kernel_setting(&current_raw);
    trace!("Parsed lockdown setting '{}' to '{}'", current_raw, current);

    // The kernel doesn't allow rewriting the current value.
    if current == lockdown {
        info!("Requested lockdown setting is already in effect.");
        return Ok(());
    // As described above, the kernel doesn't allow lowering the value.
    } else if current == "confidentiality" || (current == "integrity" && lockdown == "none") {
        warn!("Can't lower lockdown setting at runtime; please reboot for it to take effect.",);
        return Ok(());
    }

    fs::write(LOCKDOWN_PATH, lockdown).context(error::LockdownSnafu { current, lockdown })
}

/// The Linux kernel provides human-readable output like `[none] integrity confidentiality` when
/// you read settings from virtual files like /sys/kernel/security/lockdown.  This parses out the
/// current value of the setting from that human-readable output.
///
/// There are also some files that only output the current value without the other options, so we
/// return the output as-is (except for trimming whitespace) if there are no brackets.
fn parse_kernel_setting(setting: &str) -> &str {
    let mut setting = setting.trim();
    // Take after the '['
    if let Some(idx) = setting.find('[') {
        if setting.len() > idx + 1 {
            setting = &setting[idx + 1..];
        }
    }
    // Take before the ']'
    if let Some(idx) = setting.find(']') {
        setting = &setting[..idx];
    }
    setting
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// Print a usage message in the event a bad argument is given.
fn usage() -> ! {
    let program_name = env::args().next().unwrap_or_else(|| "program".to_string());
    eprintln!(
        r"Usage: {} SUBCOMMAND [ ARGUMENTS... ]

    Subcommands:
        sysctl
        lockdown
        generate-hugepages-setting

    Global arguments:
        --config-path PATH
        --log-level trace|debug|info|warn|error

    Config path defaults to {}",
        program_name, DEFAULT_CONFIG_PATH,
    );
    process::exit(2);
}

/// Prints a more specific message before exiting through usage().
fn usage_msg<S: AsRef<str>>(msg: S) -> ! {
    eprintln!("{}\n", msg.as_ref());
    usage();
}

/// Parses the arguments to the program and return a representative `Args`.
fn parse_args(args: env::Args) -> Args {
    let mut log_level = None;
    let mut config_path = None;
    let mut subcommand = None;

    let mut iter = args.skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_ref() {
            "--log-level" => {
                let log_level_str = iter
                    .next()
                    .unwrap_or_else(|| usage_msg("Did not give argument to --log-level"));
                log_level = Some(LevelFilter::from_str(&log_level_str).unwrap_or_else(|_| {
                    usage_msg(format!("Invalid log level '{}'", log_level_str))
                }));
            }

            "--config-path" => {
                config_path = Some(
                    iter.next()
                        .unwrap_or_else(|| usage_msg("Did not give argument to --config-path")),
                )
            }

            "sysctl" | "lockdown" | "generate-hugepages-setting" => subcommand = Some(arg),

            _ => usage(),
        }
    }

    Args {
        subcommand: subcommand.unwrap_or_else(|| usage_msg("Must specify a subcommand.")),
        log_level: log_level.unwrap_or(LevelFilter::Info),
        config_path: config_path.unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_string()),
    }
}

// Returning a Result from main makes it print a Debug representation of the error, but with Snafu
// we have nice Display representations of the error, so we wrap "main" (run) and print any error.
// https://github.com/shepmaster/snafu/issues/110
fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        process::exit(1);
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

mod error {
    use snafu::Snafu;
    use std::io;
    use std::path::PathBuf;

    #[derive(Debug, Snafu)]
    #[snafu(visibility(pub(super)))]
    pub(super) enum Error {
        #[snafu(display("Error reading config file: {}", source))]
        ReadConfigFile {
            #[snafu(source(from(io::Error, Box::new)))]
            source: Box<io::Error>,
        },

        #[snafu(display("Error deserializing config: {}", source))]
        Deserialization {
            #[snafu(source(from(toml::de::Error, Box::new)))]
            source: Box<toml::de::Error>,
        },

        #[snafu(display("Error serializing to JSON: {}", source))]
        SerializeJson { source: serde_json::error::Error },

        #[snafu(display(
            "Failed to change lockdown from '{}' to '{}': {}",
            current,
            lockdown,
            source
        ))]
        Lockdown {
            current: String,
            lockdown: String,
            source: io::Error,
        },

        #[snafu(display("Logger setup error: {}", source))]
        Logger { source: log::SetLoggerError },

        #[snafu(display("Failed to create temporary file in {}: {}", path.display(), source))]
        CreateTempFile {
            path: PathBuf,
            source: io::Error,
        },

        #[snafu(display("Failed to write sysctl config to temporary file: {}", source))]
        WriteTempFile {
            source: io::Error,
        },

        #[snafu(display("Failed to move temporary file to {}: {}", path.display(), source))]
        PersistTempFile {
            path: PathBuf,
            source: tempfile::PersistError,
        },

        #[snafu(display("Failed to run systemd-sysctl: {}", source))]
        RunSystemdSysctl {
            source: io::Error,
        },

        #[snafu(display("systemd-sysctl failed with exit code: {}", status))]
        SystemdSysctlFailed {
            status: std::process::ExitStatus,
        },
    }
}
type Result<T> = std::result::Result<T, error::Error>;

#[cfg(test)]
mod test {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use tempfile::TempDir;
    use test_case::test_case;

    /// Mock command executor for testing
    struct MockCommandExecutor {
        success: bool,
    }

    impl MockCommandExecutor {
        fn new(success: bool) -> Self {
            Self { success }
        }
    }

    impl CommandExecutor for MockCommandExecutor {
        fn execute(&self, _cmd: &str) -> std::io::Result<std::process::ExitStatus> {
            Ok(ExitStatus::from_raw(if self.success { 0 } else { 1 }))
        }
    }

    // Helper to create a temporary directory for testing
    fn setup_test_dir() -> TempDir {
        TempDir::new().expect("Failed to create temp directory")
    }

    #[test]
    fn test_generate_sysctl_config() {
        let mut sysctls = HashMap::new();
        sysctls.insert("net.ipv4.ip_forward", "1".to_string());
        sysctls.insert("vm.swappiness", "60".to_string());
        sysctls.insert("kernel.pid_max", "4194304 ".to_string()); // Note the trailing space

        let config = generate_sysctl_config(&sysctls);

        // Split into lines and sort for consistent comparison
        let mut lines: Vec<&str> = config.lines().collect();
        lines.sort();

        assert_eq!(
            lines,
            vec![
                "kernel.pid_max = 4194304",
                "net.ipv4.ip_forward = 1",
                "vm.swappiness = 60"
            ]
        );
    }

    #[test]
    fn test_generate_sysctl_config_empty() {
        let sysctls: HashMap<String, String> = HashMap::new();
        let config = generate_sysctl_config(&sysctls);
        assert_eq!(config, "");
    }

    #[test]
    fn test_persist_sysctl_config() {
        let temp_dir = setup_test_dir();
        let config = "net.ipv4.ip_forward = 1\nvm.swappiness = 60\n";
        let filename = "test-sysctl.conf";

        let config_path = persist_sysctl_config(
            config,
            temp_dir.path().to_str().unwrap(),
            filename,
        ).unwrap();

        // Verify the config file was written correctly
        let written_config = fs::read_to_string(&config_path).unwrap();
        assert_eq!(written_config, config);
    }

    #[test]
    fn test_persist_sysctl_config_invalid_dir() {
        let config = "net.ipv4.ip_forward = 1\n";
        let result = persist_sysctl_config(config, "/nonexistent", "test.conf");
        assert!(matches!(result, Err(error::Error::CreateTempFile { .. })));
    }

    #[test]
    fn test_apply_sysctl_config_success() {
        let executor = MockCommandExecutor::new(true);
        let result = apply_sysctl_config(SYSTEMD_SYSCTL_BIN, &executor);
        assert!(result.is_ok());
    }

    #[test]
    fn test_apply_sysctl_config_failure() {
        let executor = MockCommandExecutor::new(false);
        let result = apply_sysctl_config(SYSTEMD_SYSCTL_BIN, &executor);
        assert!(matches!(result, Err(error::Error::SystemdSysctlFailed { .. })));
    }

    #[test]
    fn brackets() {
        assert_eq!(
            "none",
            parse_kernel_setting("[none] integrity confidentiality")
        );
        assert_eq!(
            "integrity",
            parse_kernel_setting("none [integrity] confidentiality\n")
        );
        assert_eq!(
            "confidentiality",
            parse_kernel_setting("none integrity [confidentiality]")
        );
    }

    #[test]
    fn no_brackets() {
        assert_eq!("none", parse_kernel_setting("none"));
        assert_eq!(
            "none integrity confidentiality",
            parse_kernel_setting("none integrity confidentiality\n")
        );
    }

    #[test]
    fn test_compute_hugepages_for_efa() {
        let num_cores: usize = 2;
        let computed_hugepages = compute_hugepages_for_efa(num_cores);
        assert_eq!(computed_hugepages, "220")
    }

    #[test_case("".to_string(), "0".to_string())]
    #[test_case("0".to_string(), "0".to_string())]
    #[test_case("-1".to_string(), "0".to_string())]
    #[test_case("abc".to_string(), "0".to_string())]
    #[test_case("100".to_string(), "100".to_string())]
    fn test_check_for_existing_hugepages(existing_value: String, expected_hugepages: String) {
        let actual_hugepages = check_for_existing_hugepages(existing_value);
        assert_eq!(actual_hugepages, expected_hugepages);
    }
}
