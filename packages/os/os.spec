%global _cross_first_party 1
%undefine _debugsource_packages

Name: %{_cross_os}os
Version: 0.0
Release: 1%{?dist}
Epoch: 1
Summary: Bottlerocket's first-party code
License: Apache-2.0 OR MIT
URL: https://github.com/bottlerocket-os/bottlerocket

# sources < 100: misc
Source2: api-sysusers.conf
# Generated by https://github.com/aws/amazon-vpc-cni-k8s/blob/master/scripts/gen_vpc_ip_limits.go
Source3: eni-max-pods

# updog requires a root.json as the root of trust for repos, but the right one
# can't be known until the image is built.
#SourceX: root.json

Source5: updog-toml
Source6: metricdog-toml
Source7: host-ctr-toml
Source8: oci-default-hooks-json
Source9: cfsignal-toml
Source10: warm-pool-wait-toml
Source11: bottlerocket-cis-checks-metadata-json
Source13: kubernetes-cis-checks-metadata-json
Source14: certdog-toml
Source15: prairiedog-toml
Source16: thar-be-updates-toml
Source17: corndog-toml
Source18: bootstrap-containers-toml
Source19: host-containers-toml
Source20: bottlerocket-fips-checks-metadata-json
Source21: bootstrap-commands-toml

# 1xx sources: systemd units
Source100: apiserver.service
Source102: sundog.service
Source103: storewolf.service
Source105: settings-applier.service
Source106: migrator.service
Source107: host-containers@.service
Source110: mark-successful-boot.service
Source111: metricdog.service
Source112: metricdog.timer
Source113: send-boot-success.service
Source114: bootstrap-containers@.service
Source119: cfsignal.service
Source120: reboot-if-required.service
Source121: warm-pool-wait.service
Source122: has-boot-ever-succeeded.service
Source123: pluto.service
Source124: bootstrap-commands.service

# 2xx sources: tmpfilesd configs
Source200: migration-tmpfiles.conf
Source201: host-containers-tmpfiles.conf
Source202: thar-be-updates-tmpfiles.conf
Source203: bootstrap-containers-tmpfiles.conf
Source204: storewolf-tmpfiles.conf
Source205: bootstrap-commands-tmpfiles.conf

# 3xx sources: udev rules
Source300: ephemeral-storage.rules
Source301: ebs-volumes.rules
Source302: supplemental-storage.rules

# 4xx sources: Bottlerocket licenses
Source400: COPYRIGHT
Source401: LICENSE-MIT
Source402: LICENSE-APACHE

BuildRequires: %{_cross_os}glibc-devel
Requires: %{_cross_os}apiclient
Requires: %{_cross_os}apiserver
Requires: %{_cross_os}bloodhound
Requires: %{_cross_os}bootstrap-commands
Requires: %{_cross_os}corndog
Requires: %{_cross_os}certdog
Requires: %{_cross_os}ghostdog
Requires: %{_cross_os}logdog
Requires: %{_cross_os}metricdog
Requires: %{_cross_os}prairiedog
Requires: %{_cross_os}schnauzer
Requires: %{_cross_os}settings-committer
Requires: %{_cross_os}shimpei
Requires: %{_cross_os}signpost
Requires: %{_cross_os}storewolf
Requires: %{_cross_os}sundog
Requires: %{_cross_os}xfscli
Requires: %{_cross_os}thar-be-settings

Requires: (%{_cross_os}bootstrap-containers or %{_cross_os}image-feature(no-host-containers))
Requires: (%{_cross_os}host-containers or %{_cross_os}image-feature(no-host-containers))

Requires: (%{_cross_os}bork or %{_cross_os}image-feature(no-in-place-updates))
Requires: (%{_cross_os}migration or %{_cross_os}image-feature(no-in-place-updates))
Requires: (%{_cross_os}thar-be-updates or %{_cross_os}image-feature(no-in-place-updates))
Requires: (%{_cross_os}updog or %{_cross_os}image-feature(no-in-place-updates))

Requires: (%{_cross_os}pluto if %{_cross_os}variant-family(aws-k8s))
Requires: (%{_cross_os}shibaken if %{_cross_os}variant-platform(aws))
Requires: (%{_cross_os}cfsignal if %{_cross_os}variant-platform(aws))

Requires: (%{_cross_os}warm-pool-wait if %{_cross_os}variant-family(aws-k8s))

Requires: (%{_cross_os}driverdog if %{_cross_os}variant-flavor(nvidia))

%description
%{summary}.

%package -n %{_cross_os}apiserver
Summary: Bottlerocket API server
Requires: %{_cross_os}settings-plugins
%description -n %{_cross_os}apiserver
%{summary}.

%package -n %{_cross_os}apiclient
Summary: Bottlerocket API client
Requires: %{_cross_os}apiclient(binaries)
%description -n %{_cross_os}apiclient
%{summary}.

%package -n %{_cross_os}apiclient-bin
Summary: Bottlerocket API client binaries
Provides: %{_cross_os}apiclient(binaries)
Requires: (%{_cross_os}image-feature(no-fips) and %{_cross_os}apiclient)
Conflicts: (%{_cross_os}image-feature(fips) or %{_cross_os}apiclient-fips-bin)
%description -n %{_cross_os}apiclient-bin
%{summary}.

%package -n %{_cross_os}apiclient-fips-bin
Summary: Bottlerocket API client binaries, FIPS edition
Provides: %{_cross_os}apiclient(binaries)
Requires: (%{_cross_os}image-feature(fips) and %{_cross_os}apiclient)
Conflicts: (%{_cross_os}image-feature(no-fips) or %{_cross_os}apiclient-bin)
%description -n %{_cross_os}apiclient-fips-bin
%{summary}.

%package -n %{_cross_os}sundog
Summary: Updates settings dynamically based on user-specified generators
%description -n %{_cross_os}sundog
%{summary}.

%package -n %{_cross_os}bork
Summary: Dynamic setting generator for updog
Conflicts: %{_cross_os}image-feature(no-in-place-updates)
%description -n %{_cross_os}bork
%{summary}.

%package -n %{_cross_os}corndog
Summary: Bottlerocket sysctl helper
%description -n %{_cross_os}corndog
%{summary}.

%package -n %{_cross_os}schnauzer
Summary: Setting generator for templated settings values.
%description -n %{_cross_os}schnauzer
%{summary}.

%package -n %{_cross_os}thar-be-settings
Summary: Applies changed settings to a Bottlerocket system
%description -n %{_cross_os}thar-be-settings
%{summary}.

%package -n %{_cross_os}thar-be-updates
Summary: Dispatches Bottlerocket update commands
Conflicts: %{_cross_os}image-feature(no-in-place-updates)
%description -n %{_cross_os}thar-be-updates
%{summary}.

%package -n %{_cross_os}host-containers
Summary: Manages system- and user-defined host containers
Requires: %{_cross_os}host-ctr
Conflicts: %{_cross_os}image-feature(no-host-containers)
%description -n %{_cross_os}host-containers
%{summary}.

%package -n %{_cross_os}storewolf
Summary: Data store creator
Requires: %{_cross_os}settings-defaults
%description -n %{_cross_os}storewolf
%{summary}.

%package -n %{_cross_os}migration
Summary: Tools to migrate version formats
Conflicts: %{_cross_os}image-feature(no-in-place-updates)
Requires: %{_cross_os}migration(binaries)
%description -n %{_cross_os}migration

%package -n %{_cross_os}migration-bin
Summary: Binaries to migrate version formats
Provides: %{_cross_os}migration(binaries)
Requires: (%{_cross_os}image-feature(no-fips) and %{_cross_os}migration)
Conflicts: %{_cross_os}image-feature(no-in-place-updates)
Conflicts: (%{_cross_os}image-feature(fips) or %{_cross_os}migration-fips-bin)
%description -n %{_cross_os}migration-bin
%{summary}.

%package -n %{_cross_os}migration-fips-bin
Summary: Binaries to migrate version formats, FIPS edition
Provides: %{_cross_os}migration(binaries)
Requires: (%{_cross_os}image-feature(fips) and %{_cross_os}migration)
Conflicts: %{_cross_os}image-feature(no-in-place-updates)
Conflicts: (%{_cross_os}image-feature(no-fips) or %{_cross_os}migration-bin)
%description -n %{_cross_os}migration-fips-bin
%{summary}.

%package -n %{_cross_os}settings-committer
Summary: Commits settings from user data, defaults, and generators at boot
%description -n %{_cross_os}settings-committer
%{summary}.

%package -n %{_cross_os}ghostdog
Summary: Tool to manage ephemeral disks
Requires: %{_cross_os}nvme-cli
%description -n %{_cross_os}ghostdog
%{summary}.

%package -n %{_cross_os}signpost
Summary: Bottlerocket GPT priority querier/switcher
%description -n %{_cross_os}signpost
%{summary}.

%package -n %{_cross_os}updog
Summary: Bottlerocket updater CLI
Requires: %{_cross_os}updog(binaries)
Conflicts: %{_cross_os}image-feature(no-in-place-updates)
%description -n %{_cross_os}updog
not much what's up with you

%package -n %{_cross_os}updog-bin
Summary: Bottlerocket updater CLI binaries
Provides: %{_cross_os}updog(binaries)
Requires: (%{_cross_os}image-feature(no-fips) and %{_cross_os}updog)
Conflicts: %{_cross_os}image-feature(no-in-place-updates)
Conflicts: %{_cross_os}image-feature(fips) or %{_cross_os}updog-fips-bin
%description -n %{_cross_os}updog-bin
%{summary}.

%package -n %{_cross_os}updog-fips-bin
Summary: Bottlerocket updater CLI binaries, FIPS edition
Provides: %{_cross_os}updog(binaries)
Requires: (%{_cross_os}image-feature(fips) and %{_cross_os}updog)
Conflicts: %{_cross_os}image-feature(no-in-place-updates)
Conflicts: %{_cross_os}image-feature(no-fips) or %{_cross_os}updog-bin
%description -n %{_cross_os}updog-fips-bin
%{summary}.

%package -n %{_cross_os}metricdog
Summary: Bottlerocket health metrics sender
Requires: %{_cross_os}metricdog(binaries)
%description -n %{_cross_os}metricdog
%{summary}.

%package -n %{_cross_os}metricdog-bin
Summary: Bottlerocket health metrics sender binaries
Provides: %{_cross_os}metricdog(binaries)
Requires: (%{_cross_os}image-feature(no-fips) and %{_cross_os}metricdog)
Conflicts: (%{_cross_os}image-feature(fips) or %{_cross_os}metricdog-fips-bin)
%description -n %{_cross_os}metricdog-bin
%{summary}.

%package -n %{_cross_os}metricdog-fips-bin
Summary: Bottlerocket health metrics sender binaries, FIPS edition
Provides: %{_cross_os}metricdog(binaries)
Requires: (%{_cross_os}image-feature(fips) and %{_cross_os}metricdog)
Conflicts: (%{_cross_os}image-feature(no-fips) or %{_cross_os}metricdog-bin)
%description -n %{_cross_os}metricdog-fips-bin
%{summary}.

%package -n %{_cross_os}logdog
Summary: Bottlerocket log extractor
Requires: %{_cross_os}logdog(binaries)
%description -n %{_cross_os}logdog
%{summary}.

%package -n %{_cross_os}logdog-bin
Summary: Bottlerocket log extractor binaries
Provides: %{_cross_os}logdog(binaries)
Requires: (%{_cross_os}image-feature(no-fips) and %{_cross_os}logdog)
Conflicts: (%{_cross_os}image-feature(fips) or %{_cross_os}logdog-fips-bin)
%description -n %{_cross_os}logdog-bin
%{summary}.

%package -n %{_cross_os}logdog-fips-bin
Summary: Bottlerocket log extractor binaries, FIPS edition
Provides: %{_cross_os}logdog(binaries)
Requires: (%{_cross_os}image-feature(fips) and %{_cross_os}logdog)
Conflicts: (%{_cross_os}image-feature(no-fips) or %{_cross_os}logdog-bin)
%description -n %{_cross_os}logdog-fips-bin
%{summary}.

%package -n %{_cross_os}prairiedog
Summary: Tools for kdump support
Requires: %{_cross_os}kexec-tools
Requires: %{_cross_os}makedumpfile
%description -n %{_cross_os}prairiedog
%{summary}.

%package -n %{_cross_os}certdog
Summary: Bottlerocket certificates handler
%description -n %{_cross_os}certdog
%{summary}.

%package -n %{_cross_os}pluto
Summary: Dynamic setting generator for kubernetes
Requires: %{_cross_os}pluto(binaries)
%description -n %{_cross_os}pluto
%{summary}.

%package -n %{_cross_os}pluto-bin
Summary: Dynamic setting generator for kubernetes binaries
Provides: %{_cross_os}pluto(binaries)
Requires: (%{_cross_os}image-feature(no-fips) and %{_cross_os}pluto)
Conflicts: (%{_cross_os}image-feature(fips) or %{_cross_os}pluto-fips-bin)
%description -n %{_cross_os}pluto-bin
%{summary}.

%package -n %{_cross_os}pluto-fips-bin
Summary: Dynamic setting generator for kubernetes binaries, FIPS edition
Provides: %{_cross_os}pluto(binaries)
Requires: (%{_cross_os}image-feature(fips) and %{_cross_os}pluto)
Conflicts: (%{_cross_os}image-feature(no-fips) or %{_cross_os}pluto-bin)
%description -n %{_cross_os}pluto-fips-bin
%{summary}.

%package -n %{_cross_os}shibaken
Summary: IMDS client and settings generator
Requires: %{_cross_os}shibaken(binaries)
%description -n %{_cross_os}shibaken
%{summary}.

%package -n %{_cross_os}shibaken-bin
Summary: IMDS client and settings generator binaries
Provides: %{_cross_os}shibaken(binaries)
Requires: (%{_cross_os}image-feature(no-fips) and %{_cross_os}shibaken)
Conflicts: (%{_cross_os}image-feature(fips) or %{_cross_os}shibaken-fips-bin)
%description -n %{_cross_os}shibaken-bin
%{summary}.

%package -n %{_cross_os}shibaken-fips-bin
Summary: IMDS client and settings generator binaries, FIPS edition
Provides: %{_cross_os}shibaken(binaries)
Requires: (%{_cross_os}image-feature(fips) and %{_cross_os}shibaken)
Conflicts: (%{_cross_os}image-feature(no-fips) or %{_cross_os}shibaken-bin)
%description -n %{_cross_os}shibaken-fips-bin
%{summary}.

%package -n %{_cross_os}warm-pool-wait
Summary: Warm pool wait for aws k8s
Requires: %{_cross_os}shibaken
%description -n %{_cross_os}warm-pool-wait
%{summary}.

%package -n %{_cross_os}cfsignal
Summary: Bottlerocket CloudFormation Stack signaler
Requires: %{_cross_os}cfsignal(binaries)
%description -n %{_cross_os}cfsignal
%{summary}.

%package -n %{_cross_os}cfsignal-bin
Summary: Bottlerocket CloudFormation Stack signaler binaries
Provides: %{_cross_os}cfsignal(binaries)
Requires: (%{_cross_os}image-feature(no-fips) and %{_cross_os}cfsignal)
Conflicts: (%{_cross_os}image-feature(fips) or %{_cross_os}cfsignal-fips-bin)
%description -n %{_cross_os}cfsignal-bin
%{summary}.

%package -n %{_cross_os}cfsignal-fips-bin
Summary: Bottlerocket CloudFormation Stack signaler binaries, FIPS edition
Provides: %{_cross_os}cfsignal(binaries)
Requires: (%{_cross_os}image-feature(fips) and %{_cross_os}cfsignal)
Conflicts: (%{_cross_os}image-feature(no-fips) or %{_cross_os}cfsignal-bin)
%description -n %{_cross_os}cfsignal-fips-bin
%{summary}.

%package -n %{_cross_os}shimpei
Summary: OCI-compatible shim around oci-add-hooks
Requires: %{_cross_os}oci-add-hooks
%description -n %{_cross_os}shimpei
%{summary}.

%package -n %{_cross_os}driverdog
Summary: Tool to load additional drivers
Requires: %{_cross_os}binutils
%description -n %{_cross_os}driverdog
%{summary}.

%package -n %{_cross_os}bootstrap-commands
Summary: Manages bootstrap-commands
%description -n %{_cross_os}bootstrap-commands
%{summary}.

%package -n %{_cross_os}bootstrap-containers
Summary: Manages bootstrap-containers
Requires: %{_cross_os}host-ctr
Conflicts: %{_cross_os}image-feature(no-host-containers)
%description -n %{_cross_os}bootstrap-containers
%{summary}.

%package -n %{_cross_os}bloodhound
Summary: Compliance check framework
Requires: (%{_cross_os}bloodhound-k8s if %{_cross_os}variant-runtime(k8s))
Requires: (%{_cross_os}bloodhound-fips if %{_cross_os}image-feature(fips))
%description -n %{_cross_os}bloodhound
%{summary}.

%package -n %{_cross_os}bloodhound-k8s
Summary: Compliance checks for Kubernetes
Requires: (%{_cross_os}bloodhound and %{_cross_os}variant-runtime(k8s))
%description -n %{_cross_os}bloodhound-k8s
%{summary}.

%package -n %{_cross_os}bloodhound-fips
Summary: Compliance checks for FIPS
Requires: (%{_cross_os}bloodhound and %{_cross_os}image-feature(fips))
%description -n %{_cross_os}bloodhound-fips
%{summary}.

%package -n %{_cross_os}xfscli
Summary: XFS progs cli
%description -n %{_cross_os}xfscli
%{summary}.

%prep
%setup -T -c
%cargo_prep

# Some of the AWS-LC sources are built with `-O0`. This is not compatible with
# `-Wp,-D_FORTIFY_SOURCE=2`, which needs at least `-O2`.
sed -i 's/-Wp,-D_FORTIFY_SOURCE=2//g' \
  %_cross_cmake_toolchain_conf \
  %_cross_cmake_toolchain_conf_static

%build
mkdir bin

# We want to build apiclient statically, because it needs to run from containers that don't have
# the same libraries available.
#
# Most of our components don't need to be static, though.  This means we run cargo once for static
# and once for non-static.  There's a long tail of crate builds for each of these that can be
# mitigated by running them in parallel, saving a fair amount of time.  To do this, we kick off the
# static build in the background, run the non-static (main) build in the foreground, and then wait
# for the static build and print its output afterward.  A failure of either will stop the build.

# Since RPM automatically logs the commands that run, and since we want to display those commands
# along with the output from the background job, we do some file descriptor juggling below.
#  exec 3>&1 4>&2           - save stdout and stderr to fds 3 and 4
#  exec 1>"${output}" 2>&1  - redirect stdout and stderr to job-specific log
#  exec 1>&3 2>&4           - restore stdout and stderr from fds 3 and 4

# Store the output so we can print it after waiting for the backgrounded job.
exec 3>&1 4>&2
static_output="$(mktemp)"
exec 1>"${static_output}" 2>&1
# Build static binaries in the background.
%cargo_build_static --manifest-path %{_builddir}/sources/Cargo.toml \
    -p apiclient \
    &
# Save the PID so we can wait for it later.
static_pid="$!"
exec 1>&3 2>&4

exec 3>&1 4>&2
static_fips_output="$(mktemp)"
exec 1>"${static_fips_output}" 2>&1

# Build static binaries in the background.
%cargo_build_static_fips --manifest-path %{_builddir}/sources/Cargo.toml \
    -p apiclient \
    &
# Save the PID so we can wait for it later.
static_fips_pid="$!"
exec 1>&3 2>&4

# Pessimize the release build for the crates with slow builds, e.g. those that
# depend on the AWS SDK crates.
# Store the output so we can print it after waiting for the backgrounded job.
exec 3>&1 4>&2
aws_sdk_output="$(mktemp)"
exec 1>"${aws_sdk_output}" 2>&1
  %cargo_build_aws_sdk --manifest-path %{_builddir}/sources/Cargo.toml \
  -p pluto \
  -p cfsignal \
  &
# Save the PID so we can wait for it later.
aws_sdk_pid="$!"
exec 1>&3 2>&4

exec 3>&1 4>&2
fips_aws_sdk_output="$(mktemp)"
exec 1>"${fips_aws_sdk_output}" 2>&1
  %cargo_build_fips_aws_sdk --manifest-path %{_builddir}/sources/Cargo.toml \
  -p pluto \
  -p cfsignal \
  &
# Save the PID so we can wait for it later.
fips_aws_sdk_pid="$!"
exec 1>&3 2>&4

# Build non-static FIPS builds in the background
exec 3>&1 4>&2
fips_output="$(mktemp)"
exec 1>"${fips_output}" 2>&1
  %cargo_build_fips --manifest-path %{_builddir}/sources/Cargo.toml \
    -p logdog \
    -p metricdog \
    -p migrator \
    -p updog \
    -p shibaken \
    &
# Save the PID so we can wait for it later.
fips_pid="$!"
exec 1>&3 2>&4

# Run non-static builds in the foreground.
echo "** Output from non-static builds:"
%cargo_build --manifest-path %{_builddir}/sources/Cargo.toml \
    -p apiserver \
    -p sundog \
    -p schnauzer \
    -p bork \
    -p thar-be-settings \
    -p thar-be-updates \
    -p host-containers \
    -p storewolf \
    -p settings-committer \
    -p migrator \
    -p signpost \
    -p updog \
    -p logdog \
    -p metricdog \
    -p ghostdog \
    -p corndog \
    -p bootstrap-commands \
    -p bootstrap-containers \
    -p prairiedog \
    -p certdog \
    -p shimpei \
    -p bloodhound \
    -p xfscli \
    -p shibaken \
    -p driverdog \
    %{nil}

# Wait for fips builds from the background, if they're not already done.
set +e; wait "${fips_pid}"; fips_rc="${?}"; set -e
echo -e "\n** Output from FIPS builds:"
cat "${fips_output}"

# Wait for static builds from the background, if they're not already done.
set +e; wait "${static_pid}"; static_rc="${?}"; set -e
echo -e "\n** Output from static builds:"
cat "${static_output}"

set +e; wait "${static_fips_pid}"; static_fips_rc="${?}"; set -e
echo -e "\n** Output from FIPS static builds:"
cat "${static_fips_output}"

# Wait for AWS SDK builds from the background, if they're not already done.
set +e; wait "${aws_sdk_pid}"; aws_sdk_rc="${?}"; set -e
echo -e "\n** Output from AWS SDK builds:"
cat "${aws_sdk_output}"

set +e; wait "${fips_aws_sdk_pid}"; fips_aws_sdk_rc="${?}"; set -e
echo -e "\n** Output from AWS SDK FIPS builds:"
cat "${fips_aws_sdk_output}"

if [ "${fips_rc}" -ne 0 ]; then
   exit "${fips_rc}"
fi

if [ "${fips_aws_sdk_rc}" -ne 0 ]; then
   exit "${fips_aws_sdk_rc}"
fi

if [ "${static_fips_rc}" -ne 0 ]; then
   exit "${static_fips_rc}"
fi

if [ "${static_rc}" -ne 0 ]; then
   exit "${static_rc}"
fi

if [ "${aws_sdk_rc}" -ne 0 ]; then
   exit "${aws_sdk_rc}"
fi


%install
install -d %{buildroot}%{_cross_bindir}
install -d %{buildroot}%{_cross_fips_bindir}
for p in \
  apiserver \
  sundog schnauzer schnauzer-v2 bork \
  corndog thar-be-settings thar-be-updates host-containers \
  storewolf settings-committer \
  migrator prairiedog certdog \
  signpost updog metricdog logdog \
  ghostdog bootstrap-commands bootstrap-containers \
  shimpei bloodhound \
  bottlerocket-cis-checks \
  bottlerocket-fips-checks \
  kubernetes-cis-checks \
  shibaken \
  driverdog \
; do
  install -p -m 0755 %{__cargo_outdir}/${p} %{buildroot}%{_cross_bindir}
done

for p in \
  logdog migrator metricdog \
  shibaken updog \
; do
  install -p -m 0755 %{__cargo_outdir_fips}/${p} %{buildroot}%{_cross_fips_bindir}
done

for p in \
  pluto \
  cfsignal \
; do
  install -p -m 0755 %{__cargo_outdir_aws_sdk}/${p} %{buildroot}%{_cross_bindir}
  install -p -m 0755 %{__cargo_outdir_aws_sdk_fips}/${p} %{buildroot}%{_cross_fips_bindir}
done

install -d %{buildroot}%{_cross_sbindir}
for p in \
  xfs_admin xfs_info \
; do
  install -p -m 0755 %{__cargo_outdir}/${p} %{buildroot}%{_cross_sbindir}/
done
# Rename fsck_xfs binary to fsck.xfs
install -p -m 0755 %{__cargo_outdir}/fsck_xfs %{buildroot}%{_cross_sbindir}/fsck.xfs

# Add the bloodhound checker symlinks
mkdir -p %{buildroot}%{_cross_libexecdir}/cis-checks/bottlerocket
for p in \
  br01020100 br01060000 br03040103 br03040203 \
  br01010101 br01030100 br01040100 br01040200 br01040300 br01040400 \
  br01050100 br01050200 br02010101 br03010100 br03020100 br03020200 \
  br03020300 br03020400 br03020500 br03020600 br03020700 br03030100 \
  br03040101 br03040102 br03040201 br03040202 br04010101 br04010200 \
; do
  ln -rs %{buildroot}%{_cross_bindir}/bottlerocket-cis-checks \
    %{buildroot}%{_cross_libexecdir}/cis-checks/bottlerocket/${p}
done
install -m 0644 %{S:11} %{buildroot}%{_cross_libexecdir}/cis-checks/bottlerocket/metadata.json

mkdir -p %{buildroot}%{_cross_libexecdir}/fips-checks/bottlerocket
for p in \
  fips01000000 fips01010000 fips01020000 fips01030000 \
; do
  ln -rs %{buildroot}%{_cross_bindir}/bottlerocket-fips-checks \
    %{buildroot}%{_cross_libexecdir}/fips-checks/bottlerocket/${p}
done
install -m 0644 %{S:20} %{buildroot}%{_cross_libexecdir}/fips-checks/bottlerocket/metadata.json

# Only add the k8s checks if it is a k8s variant
mkdir -p %{buildroot}%{_cross_libexecdir}/cis-checks/kubernetes
for p in \
  k8s04010300 k8s04010400 k8s04020700 k8s04020800 \
  k8s04010100 k8s04010200 k8s04010500 k8s04010600 k8s04010700 \
  k8s04010800 k8s04010900 k8s04011000 k8s04020100 k8s04020200 \
  k8s04020300 k8s04020400 k8s04020500 k8s04020600 k8s04020900 \
  k8s04021000 k8s04021100 k8s04021200 k8s04021300 \
; do
  ln -rs %{buildroot}%{_cross_bindir}/kubernetes-cis-checks \
    %{buildroot}%{_cross_libexecdir}/cis-checks/kubernetes/${p}
done
install -m 0644 %{S:13} %{buildroot}%{_cross_libexecdir}/cis-checks/kubernetes/metadata.json

for p in apiclient ; do
  install -p -m 0755 %{__cargo_outdir_static}/${p} %{buildroot}%{_cross_bindir}
  install -p -m 0755 %{__cargo_outdir_static_fips}/${p} %{buildroot}%{_cross_fips_bindir}
done

install -d %{buildroot}%{_cross_datadir}/bottlerocket

install -d %{buildroot}%{_cross_sysusersdir}
install -p -m 0644 %{S:2} %{buildroot}%{_cross_sysusersdir}/api.conf

install -d %{buildroot}%{_cross_datadir}/eks
install -p -m 0644 %{S:3} %{buildroot}%{_cross_datadir}/eks

# Always install updog's data directory.
install -d %{buildroot}%{_cross_datadir}/updog

# Older versions of Twoliter arranged to copy root.json into place by way of the
# Dockerfile, and made its path available in the _cross_repo_root_json macro.
# Newer versions defer the install of root.json to image creation time instead,
# so the file may not be present.
if [ -s "%{_cross_repo_root_json}" ] ; then
  install -p -m 0644 %{_cross_repo_root_json} %{buildroot}%{_cross_datadir}/updog
fi

install -d %{buildroot}%{_cross_templatedir}
install -p -m 0644 %{S:5} %{S:6} %{S:7} %{S:8} %{S:14} %{S:15} %{S:16} %{S:17} %{S:18} %{S:19} %{S:21} \
  %{buildroot}%{_cross_templatedir}

install -d %{buildroot}%{_cross_unitdir}
install -p -m 0644 \
  %{S:100} %{S:102} %{S:103} %{S:105} \
  %{S:106} %{S:107} %{S:110} %{S:111} %{S:112} \
  %{S:113} %{S:114} %{S:120} %{S:122} %{S:123} %{S:124} \
  %{buildroot}%{_cross_unitdir}

install -p -m 0644 %{S:10} %{buildroot}%{_cross_templatedir}
install -p -m 0644 %{S:121} %{buildroot}%{_cross_unitdir}

install -p -m 0644 %{S:9} %{buildroot}%{_cross_templatedir}
install -p -m 0644 %{S:119} %{buildroot}%{_cross_unitdir}

install -d %{buildroot}%{_cross_tmpfilesdir}
install -p -m 0644 %{S:200} %{buildroot}%{_cross_tmpfilesdir}/migration.conf
install -p -m 0644 %{S:201} %{buildroot}%{_cross_tmpfilesdir}/host-containers.conf
install -p -m 0644 %{S:202} %{buildroot}%{_cross_tmpfilesdir}/thar-be-updates.conf
install -p -m 0644 %{S:203} %{buildroot}%{_cross_tmpfilesdir}/bootstrap-containers.conf
install -p -m 0644 %{S:204} %{buildroot}%{_cross_tmpfilesdir}/storewolf.conf
install -p -m 0644 %{S:205} %{buildroot}%{_cross_tmpfilesdir}/bootstrap-commands.conf

install -d %{buildroot}%{_cross_udevrulesdir}
install -p -m 0644 %{S:300} %{buildroot}%{_cross_udevrulesdir}/80-ephemeral-storage.rules
install -p -m 0644 %{S:301} %{buildroot}%{_cross_udevrulesdir}/81-ebs-volumes.rules
install -p -m 0644 %{S:302} %{buildroot}%{_cross_udevrulesdir}/82-supplemental-storage.rules

%cross_scan_attribution --clarify %{_builddir}/sources/clarify.toml \
    cargo --offline --locked %{_builddir}/sources/Cargo.toml

# Install licenses
install -d %{buildroot}%{_cross_licensedir}
install -p -m 0644 %{S:400} %{S:401} %{S:402} %{buildroot}%{_cross_licensedir}

%files
%{_cross_attribution_vendor_dir}
%{_cross_licensedir}/COPYRIGHT
%{_cross_licensedir}/LICENSE-MIT
%{_cross_licensedir}/LICENSE-APACHE

%files -n %{_cross_os}apiserver
%{_cross_bindir}/apiserver
%{_cross_unitdir}/apiserver.service
%{_cross_sysusersdir}/api.conf

%files -n %{_cross_os}apiclient

%files -n %{_cross_os}apiclient-bin
%{_cross_bindir}/apiclient

%files -n %{_cross_os}apiclient-fips-bin
%{_cross_fips_bindir}/apiclient

%files -n %{_cross_os}corndog
%{_cross_bindir}/corndog
%{_cross_templatedir}/corndog-toml

%files -n %{_cross_os}sundog
%{_cross_bindir}/sundog
%{_cross_unitdir}/sundog.service

%files -n %{_cross_os}schnauzer
%{_cross_bindir}/schnauzer
%{_cross_bindir}/schnauzer-v2

%files -n %{_cross_os}bork
%{_cross_bindir}/bork

%files -n %{_cross_os}thar-be-settings
%{_cross_bindir}/thar-be-settings
%{_cross_unitdir}/settings-applier.service

%files -n %{_cross_os}thar-be-updates
%{_cross_bindir}/thar-be-updates
%{_cross_tmpfilesdir}/thar-be-updates.conf
%{_cross_templatedir}/thar-be-updates-toml

%files -n %{_cross_os}host-containers
%{_cross_bindir}/host-containers
%{_cross_unitdir}/host-containers@.service
%{_cross_tmpfilesdir}/host-containers.conf
%dir %{_cross_templatedir}
%{_cross_templatedir}/host-ctr-toml
%{_cross_templatedir}/host-containers-toml

%files -n %{_cross_os}storewolf
%{_cross_bindir}/storewolf
%{_cross_unitdir}/storewolf.service
%{_cross_tmpfilesdir}/storewolf.conf

%files -n %{_cross_os}migration
%{_cross_unitdir}/migrator.service
%{_cross_tmpfilesdir}/migration.conf

%files -n %{_cross_os}migration-bin
%{_cross_bindir}/migrator

%files -n %{_cross_os}migration-fips-bin
%{_cross_fips_bindir}/migrator

%files -n %{_cross_os}settings-committer
%{_cross_bindir}/settings-committer

%files -n %{_cross_os}ghostdog
%{_cross_bindir}/ghostdog
%{_cross_udevrulesdir}/80-ephemeral-storage.rules
%{_cross_udevrulesdir}/81-ebs-volumes.rules
%{_cross_udevrulesdir}/82-supplemental-storage.rules

%files -n %{_cross_os}signpost
%{_cross_bindir}/signpost
%{_cross_unitdir}/mark-successful-boot.service
%{_cross_unitdir}/has-boot-ever-succeeded.service

%files -n %{_cross_os}updog
%{_cross_datadir}/updog
%dir %{_cross_templatedir}
%{_cross_templatedir}/updog-toml

%files -n %{_cross_os}updog-bin
%{_cross_bindir}/updog

%files -n %{_cross_os}updog-fips-bin
%{_cross_fips_bindir}/updog

%files -n %{_cross_os}metricdog
%dir %{_cross_templatedir}
%{_cross_templatedir}/metricdog-toml
%{_cross_unitdir}/metricdog.service
%{_cross_unitdir}/metricdog.timer
%{_cross_unitdir}/send-boot-success.service

%files -n %{_cross_os}metricdog-bin
%{_cross_bindir}/metricdog

%files -n %{_cross_os}metricdog-fips-bin
%{_cross_fips_bindir}/metricdog

%files -n %{_cross_os}logdog

%files -n %{_cross_os}logdog-bin
%{_cross_bindir}/logdog

%files -n %{_cross_os}logdog-fips-bin
%{_cross_fips_bindir}/logdog

%files -n %{_cross_os}shibaken
%dir %{_cross_templatedir}

%files -n %{_cross_os}shibaken-bin
%{_cross_bindir}/shibaken

%files -n %{_cross_os}shibaken-fips-bin
%{_cross_fips_bindir}/shibaken

%files -n %{_cross_os}warm-pool-wait
%{_cross_templatedir}/warm-pool-wait-toml
%{_cross_unitdir}/warm-pool-wait.service

%files -n %{_cross_os}cfsignal
%dir %{_cross_templatedir}
%{_cross_templatedir}/cfsignal-toml
%{_cross_unitdir}/cfsignal.service

%files -n %{_cross_os}cfsignal-bin
%{_cross_bindir}/cfsignal

%files -n %{_cross_os}cfsignal-fips-bin
%{_cross_fips_bindir}/cfsignal

%files -n %{_cross_os}driverdog
%{_cross_bindir}/driverdog

%files -n %{_cross_os}pluto
%{_cross_unitdir}/pluto.service
%dir %{_cross_datadir}/eks
%{_cross_datadir}/eks/eni-max-pods

%files -n %{_cross_os}pluto-bin
%{_cross_bindir}/pluto

%files -n %{_cross_os}pluto-fips-bin
%{_cross_fips_bindir}/pluto

%files -n %{_cross_os}shimpei
%{_cross_bindir}/shimpei
%{_cross_templatedir}/oci-default-hooks-json

%files -n %{_cross_os}prairiedog
%{_cross_bindir}/prairiedog
%{_cross_unitdir}/reboot-if-required.service
%{_cross_templatedir}/prairiedog-toml

%files -n %{_cross_os}certdog
%{_cross_bindir}/certdog
%{_cross_templatedir}/certdog-toml

%files -n %{_cross_os}bootstrap-commands
%{_cross_bindir}/bootstrap-commands
%{_cross_unitdir}/bootstrap-commands.service
%{_cross_tmpfilesdir}/bootstrap-commands.conf
%{_cross_templatedir}/bootstrap-commands-toml

%files -n %{_cross_os}bootstrap-containers
%{_cross_bindir}/bootstrap-containers
%{_cross_unitdir}/bootstrap-containers@.service
%{_cross_tmpfilesdir}/bootstrap-containers.conf
%{_cross_templatedir}/bootstrap-containers-toml

%files -n %{_cross_os}bloodhound
%{_cross_bindir}/bloodhound
%{_cross_bindir}/bottlerocket-cis-checks
%{_cross_libexecdir}/cis-checks/bottlerocket

%files -n %{_cross_os}bloodhound-k8s
%{_cross_bindir}/kubernetes-cis-checks
%{_cross_libexecdir}/cis-checks/kubernetes

%files -n %{_cross_os}bloodhound-fips
%{_cross_bindir}/bottlerocket-fips-checks
%{_cross_libexecdir}/fips-checks/bottlerocket

%files -n %{_cross_os}xfscli
%{_cross_sbindir}/xfs_admin
%{_cross_sbindir}/xfs_info
%{_cross_sbindir}/fsck.xfs

%changelog
