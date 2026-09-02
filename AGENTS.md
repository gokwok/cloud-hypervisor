## For Humans

This is a compact [AGENTS.md](https://agents.md/) file for Cloud Hypervisor.
It is meant to help automated coding agents make useful changes that stay safe,
reviewable, and compatible with the project's normal engineering constraints.

## For LLMs

### Project Context

- Start with `README.md` for the project shape and `CONTRIBUTING.md` for the
  contribution rules, coding style, commit message guidance, and LLM assistance
  disclosure policy. Following `CONTRIBUTING.md` is crucial!
- Respect `.editorconfig` when editing files, in addition to any
  language-specific formatter required by `CONTRIBUTING.md`.

### Change Guidelines

- Prefer correctness, safety, and readability over micro-optimizations. Keep
  changes small, reviewable, and aligned with the existing crate/module
  boundaries. Avoid speculative changes and unrelated refactoring.
- For API, config, migration, device model, or hypervisor boundary changes,
  consider the effect on all architectures and all backends. Changes to one
  backend can be okay if the other backend still functions properly and could
  be extended or modified later.
- Follow Rust best practices and the style already present in the touched code.
- Avoid new dependencies unless the benefit is clear and local alternatives are
  not enough.
- Preserve existing behavior unless the requested change explicitly needs a
  behavior change; refactors must preserve behavior. Call out compatibility or
  migration implications.
- Do not invent APIs, behavior, or requirements. If something is uncertain,
  state the uncertainty and proceed only with minimal, explicit assumptions.
- For `thiserror`-style errors, start messages with a capital letter and keep
  the outer `Display` text short. Put all non-`#[source]` attributes in the
  message to improve helpfulness, but do not repeat a `#[source]` value
  inline: Cloud Hypervisor prints the full error chain, so only include the
  concrete failure text directly when there is no source to report.

### Safety and Domain Notes

- Prefer safe Rust. If `unsafe` is necessary, keep it narrow, add a `SAFETY:`
  comment with the invariants, and make sure the surrounding code upholds them.
- Assume concurrency matters. Avoid races, unsynchronized shared state, and
  implicit ordering assumptions; prefer clear ownership and synchronization.

### Build and Test Notes

- Some workspace members require the `kvm` feature to build or test correctly.
  When a default build failure looks feature-related, retry the narrow command
  with `--features kvm` before widening the diagnosis.
- Prefer narrow crate/test commands while iterating, then broaden verification
  when the touched surface justifies it.
- Formatting currently needs nightly-only rustfmt features; use
  `cargo +nightly fmt --all`.
- Add targeted unit tests for bug fixes and non-trivial logic where practical.
  Keep test scaffolding minimal and focused.
- Integration tests live in `./cloud-hypervisor/tests/` and are normally driven
  by `./scripts/dev_cli.sh` / `./scripts/run_integration_tests_*.sh`. They need
  host privileges, workloads, and container setup. To build the integration-test
  code directly without the infrastructure from `./scripts`, set the Rust cfg
  `devcli_testenv` or simply build through `clippy` which automatically includes
  these code paths; otherwise the integration-test code is not included.

#### Maintained x86_64 musl release build

- Build the release binary on `gw-ubuntu` in the pinned container image
  `ghcr.io/cloud-hypervisor/cloud-hypervisor:20260522-0`; do not substitute a
  different container tag for release artifacts.
- Mount the `gw-ubuntu` stable Rust toolchain into the container. The image's
  Rust 1.89 musl sysroot lacks `preadv2` and `pwritev2`, while the validated
  stable toolchain supplies them. The image's distro `libcap-ng` is also
  glibc-linked, so mount the verified musl build of libcap-ng 0.8.4 and select
  it explicitly. From `/home/gokwok/code/work/cloud-hypervisor`, run:

  ```sh
  docker run --rm \
    --volume "$PWD:/cloud-hypervisor" \
    --volume /home/gokwok/.cargo/git:/usr/local/rust/git \
    --volume /home/gokwok/.cargo/registry:/usr/local/rust/registry \
    --volume /home/gokwok/.rustup/toolchains/stable-x86_64-unknown-linux-gnu:/opt/rust:ro \
    --volume /home/gokwok/ch-staged-reset-ab/native/libcap-ng-0.8.4-musl:/opt/libcap-ng-musl:ro \
    --workdir /cloud-hypervisor \
    --env RUSTC=/opt/rust/bin/rustc \
    --env RUSTDOC=/opt/rust/bin/rustdoc \
    --env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
    --env CC_x86_64_unknown_linux_musl=musl-gcc \
    --env LIBCAPNG_LINK_TYPE=static \
    --env LIBCAPNG_LIB_PATH=/opt/libcap-ng-musl/lib \
    ghcr.io/cloud-hypervisor/cloud-hypervisor:20260522-0 \
    sh -lc '
      git config --global --add safe.directory /cloud-hypervisor &&
      /opt/rust/bin/cargo clean --offline -p cloud-hypervisor --release \
        --target x86_64-unknown-linux-musl &&
      /opt/rust/bin/cargo rustc --locked --offline --release \
        --target x86_64-unknown-linux-musl \
        -p cloud-hypervisor --bin cloud-hypervisor -- \
        -C link-arg=-Wl,--start-group \
        -C link-arg=/opt/libcap-ng-musl/lib/libcap-ng.a \
        -C link-arg=-lc \
        -C link-arg=-Wl,--end-group
    '
  ```

- The artifact is
  `target/x86_64-unknown-linux-musl/release/cloud-hypervisor`. Before packaging,
  verify its embedded version matches `git describe --dirty`, inspect it with
  `file`, confirm `readelf -l` has no `INTERP` segment, and confirm
  `readelf -d` has no `NEEDED` entries.

### Commit and Patch Formatting

- Follow the rules in `CONTRIBUTING.md`, including reviewable commit structure,
  valid component prefixes, 72-column commit messages, and a `Signed-off-by`
  trailer.
- Lines in a commit message that are allowed to exceed the 72-column limit are
  specified in `./scripts/gitlint/rules`.
- For LLM-assisted changes, follow the disclosure guidance in `CONTRIBUTING.md`:
  use the project's `Assisted-by:` trailer when disclosure is needed, and do not
  add `Co-authored-by` or similar trailers unless that policy changes. Prefer
  explicit version numbers, such as `Assisted-by: Claude:Opus-4.7`, rather than
  `Assisted-by: Claude:Opus-4`.
- Temporary allowances such as `#[allow(unused)]` or ignored tests are only
  acceptable if resolved within the same commit series or paired with a clear
  TODO referencing a ticket. Ask the developer if in doubt.
