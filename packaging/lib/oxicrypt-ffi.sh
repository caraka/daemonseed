#!/usr/bin/env bash
#
# oxicrypt-ffi.sh — the signed oxicrypt shared library a Linux artifact ships.
#
# Sourced by the Linux packaging scripts. daemonseed links oxicrypt through the
# `oxicrypt` crate, which binds the separately built and signed
# `liboxicrypt_ffi.so.1` at load time; the library verifies its own signature
# when it is initialised. A packaged binary therefore carries no signature of
# its own: it ships that library file unchanged beside it and finds it through
# a RUNPATH relative to `$ORIGIN`.

# The RUNPATH every packaged Linux binary is linked with: the library beside
# the binary, or in the `lib` directory next to the binary's own directory (the
# AppDir's `usr/bin` and `usr/lib`). Kept the same for every artifact so the
# packaging builds share one set of compiled dependencies.
OXICRYPT_RUNPATH='$ORIGIN:$ORIGIN/../lib'

# The library's delivered file name, which is its SONAME.
OXICRYPT_SONAME="liboxicrypt_ffi.so.1"

# Fetch the pinned release (the fetch script checks the tarball's sha256),
# check that the unpacked library is byte-identical to the tarball's member,
# and export OXICRYPT_LIB_DIR for the build and OXICRYPT_LIB_FILE for bundling.
# Takes the repo root.
oxicrypt_prepare() {
    local repo_root="$1" dir tarball member want have

    dir="$("${repo_root}/scripts/fetch-oxicrypt-ffi.sh" linux-x86_64)" || return 1
    tarball="$(find "${dir}" -maxdepth 1 -name 'oxicrypt-ffi-v*-linux-x86_64.tar.gz' | head -1)"
    [ -n "${tarball}" ] || { echo "oxicrypt-ffi: no release tarball in ${dir}" >&2; return 1; }
    member="$(basename "${tarball}" .tar.gz)/${OXICRYPT_SONAME}"
    want="$(tar -xOzf "${tarball}" "${member}" | sha256sum | cut -d' ' -f1)"
    have="$(sha256sum "${dir}/${OXICRYPT_SONAME}" | cut -d' ' -f1)"
    [ -n "${want}" ] && [ "${want}" = "${have}" ] || {
        echo "oxicrypt-ffi: ${dir}/${OXICRYPT_SONAME} (sha256 ${have}) is not the tarball's ${member} (sha256 ${want})" >&2
        return 1
    }
    export OXICRYPT_LIB_DIR="${dir}"
    export OXICRYPT_LIB_FILE="${dir}/${OXICRYPT_SONAME}"
    OXICRYPT_LIB_SHA256="${want}"
}

# Rust flags that link the target binaries with OXICRYPT_RUNPATH. RUSTFLAGS
# reach only the target artifacts under `--target`, never build scripts, and
# only this packaging build sets them.
oxicrypt_rustflags() {
    printf '%s -C link-arg=-Wl,--enable-new-dtags -C link-arg=-Wl,-rpath,%s' \
        "${RUSTFLAGS:-}" "${OXICRYPT_RUNPATH}"
}

# Copy the library into DEST_DIR unchanged and confirm the copy's digest.
oxicrypt_bundle() {
    local dest_dir="$1"
    mkdir -p "${dest_dir}"
    cp -f "${OXICRYPT_LIB_FILE}" "${dest_dir}/${OXICRYPT_SONAME}"
    chmod 0755 "${dest_dir}/${OXICRYPT_SONAME}"
    [ "$(sha256sum "${dest_dir}/${OXICRYPT_SONAME}" | cut -d' ' -f1)" = "${OXICRYPT_LIB_SHA256}" ] || {
        echo "oxicrypt-ffi: the bundled ${OXICRYPT_SONAME} differs from the release file" >&2
        return 1
    }
}

# Fail when any file needs a GLIBC symbol version above FLOOR.
# Usage: oxicrypt_check_glibc FLOOR FILE...
oxicrypt_check_glibc() {
    local floor="$1" max
    shift
    max="$(objdump -T "$@" | grep -oE 'GLIBC_[0-9.]+' | sort -u -V | tail -1 | sed 's/^GLIBC_//')"
    [ -n "${max}" ] || { echo "oxicrypt-ffi: no GLIBC version symbols found in $*" >&2; return 1; }
    [ "$(printf '%s\n%s\n' "${max}" "${floor}" | sort -V | tail -1)" = "${floor}" ] || {
        echo "oxicrypt-ffi: $* require GLIBC_${max}, above the ${floor} floor" >&2
        return 1
    }
    echo "${max}"
}
