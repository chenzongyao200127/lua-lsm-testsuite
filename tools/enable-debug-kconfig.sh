#!/bin/bash
#
# enable-debug-kconfig.sh
#
# Enable debug kernel config options in a kernel source tree before compilation.
# This script modifies .config to turn on common debug options (FPU debug,
# spinlock debug, memory debugging, etc.) and runs olddefconfig to resolve deps.
#
# Usage:
#   ./enable-debug-kconfig.sh --kernel /path/to/kernel-source
#   ./enable-debug-kconfig.sh --kernel /path/to/kernel-source --profile full
#   ./enable-debug-kconfig.sh --kernel /path/to/kernel-source --dry-run
#

set -euo pipefail

KERNEL_DIR=""
PROFILE="standard"
DRY_RUN=0
BACKUP=1

DEBUG_CONFIGS_STANDARD=(
    "CONFIG_X86_DEBUG_FPU=y"
    "CONFIG_DEBUG_SPINLOCK=y"
    "CONFIG_DEBUG_MUTEXES=y"
    "CONFIG_DEBUG_LOCK_ALLOC=y"
    "CONFIG_PROVE_LOCKING=y"
    "CONFIG_LOCK_STAT=y"
    "CONFIG_DEBUG_LOCKDEP=y"
    "CONFIG_DEBUG_SLAB=y"
    "CONFIG_DEBUG_PAGEALLOC=y"
    "CONFIG_DEBUG_OBJECTS=y"
    "CONFIG_SLUB_DEBUG_ON=y"
    "CONFIG_KASAN=y"
    "CONFIG_KCSAN=y"
    "CONFIG_SCHED_DEBUG=y"
    "CONFIG_SCHEDSTATS=y"
    "CONFIG_DEBUG_INFO=y"
    "CONFIG_DEBUG_KERNEL=y"
    "CONFIG_DEBUG_BUGVERBOSE=y"
    "CONFIG_FRAME_POINTER=y"
    "CONFIG_STACK_VALIDATION=y"
    "CONFIG_FTRACE=y"
    "CONFIG_FUNCTION_TRACER=y"
    "CONFIG_STACK_TRACER=y"
)

DEBUG_CONFIGS_FULL=(
    "${DEBUG_CONFIGS_STANDARD[@]}"
    "CONFIG_DEBUG_KMEMLEAK=y"
    "CONFIG_DEBUG_STACK_USAGE=y"
    "CONFIG_DEBUG_VM=y"
    "CONFIG_DEBUG_VIRTUAL=y"
    "CONFIG_RCU_CPU_STALL_TIMEOUT=21"
    "CONFIG_PROVE_RCU=y"
    "CONFIG_UBSAN=y"
    "CONFIG_DETECT_HUNG_TASK=y"
    "CONFIG_DEFAULT_HUNG_TASK_TIMEOUT=120"
    "CONFIG_PANIC_ON_OOPS=y"
    "CONFIG_DEBUG_LIST=y"
    "CONFIG_DEBUG_NOTIFIERS=y"
    "CONFIG_DEBUG_CREDENTIALS=y"
)

usage() {
    cat <<EOF
Usage: $(basename "$0") --kernel <kernel-source-dir> [OPTIONS]

Enable debug kernel config options before compilation.

Options:
  --kernel <dir>     Path to kernel source directory (required)
  --profile <name>   Debug profile: standard (default), full
  --no-backup        Don't backup existing .config
  --dry-run          Show what would be changed without modifying .config
  --list             List all configs in the selected profile and exit
  -h, --help         Show this help

Profiles:
  standard   Common debug options for kernel development (default)
  full       Aggressive debugging (significantly impacts performance)

Examples:
  $(basename "$0") --kernel ~/linux-5.10
  $(basename "$0") --kernel /usr/src/kernels/5.10.134 --profile full
  $(basename "$0") --kernel ./kernel-source --dry-run
EOF
    exit 0
}

log_info() {
    printf '\033[32m[INFO]\033[0m %s\n' "$*"
}

log_warn() {
    printf '\033[33m[WARN]\033[0m %s\n' "$*"
}

log_error() {
    printf '\033[31m[ERROR]\033[0m %s\n' "$*" >&2
}

validate_profile() {
    case "$PROFILE" in
        standard|full) ;;
        *)
            log_error "Unknown profile: $PROFILE"
            exit 1
            ;;
    esac
}

get_profile_configs() {
    local profile="$1"
    case "$profile" in
        standard) echo "${DEBUG_CONFIGS_STANDARD[@]}" ;;
        full)     echo "${DEBUG_CONFIGS_FULL[@]}" ;;
        *)
            log_error "Unknown profile: $profile"
            exit 1
            ;;
    esac
}

set_config_value() {
    local config_file="$1"
    local config_key="$2"
    local value="$3"
    local tmp_dir
    local tmp_file

    tmp_dir="$(dirname "$config_file")"
    tmp_file="$(mktemp "${tmp_dir}/.$(basename "$config_file").XXXXXX")"

    awk -v key="$config_key" -v value="$value" '
        index($0, key "=") == 1 { next }
        $0 == "# " key " is not set" { next }
        { print }
        END { print key "=" value }
    ' "$config_file" > "$tmp_file"
    mv "$tmp_file" "$config_file"
}

apply_config() {
    local config_file="$1"
    local key value config_key
    local -a configs

    case "$PROFILE" in
        standard) configs=("${DEBUG_CONFIGS_STANDARD[@]}") ;;
        full)     configs=("${DEBUG_CONFIGS_FULL[@]}") ;;
    esac

    local changed=0
    local skipped=0

    for entry in "${configs[@]}"; do
        config_key="${entry%%=*}"
        value="${entry#*=}"

        if grep -Fqx "${config_key}=${value}" "$config_file" 2>/dev/null; then
            ((skipped += 1))
            continue
        fi

        if [ "$DRY_RUN" -eq 1 ]; then
            if grep -Fqx "# ${config_key} is not set" "$config_file" 2>/dev/null; then
                echo "  [would enable]  ${config_key}=${value}  (currently disabled)"
            elif grep -q "^${config_key}=" "$config_file" 2>/dev/null; then
                local current
                current=$(grep -m 1 "^${config_key}=" "$config_file")
                echo "  [would change]  ${current} -> ${config_key}=${value}"
            else
                echo "  [would add]     ${config_key}=${value}  (not present)"
            fi
        else
            set_config_value "$config_file" "$config_key" "$value"
        fi
        ((changed += 1))
    done

    echo ""
    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "Dry run complete: $changed would be changed, $skipped already set."
    else
        log_info "Applied $changed config changes ($skipped already set)."
    fi
}

LIST_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel)
            if [ $# -lt 2 ] || [[ "$2" == --* ]]; then
                log_error "--kernel requires a directory"
                exit 1
            fi
            KERNEL_DIR="$2"
            shift 2
            ;;
        --profile)
            if [ $# -lt 2 ] || [[ "$2" == --* ]]; then
                log_error "--profile requires a value"
                exit 1
            fi
            PROFILE="$2"
            shift 2
            ;;
        --no-backup)
            BACKUP=0
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --list)
            LIST_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

validate_profile

if [ "$LIST_ONLY" -eq 1 ]; then
    echo "Debug configs for profile '$PROFILE':"
    echo ""
    local_configs=$(get_profile_configs "$PROFILE")
    for c in $local_configs; do
        echo "  $c"
    done
    exit 0
fi

if [ -z "$KERNEL_DIR" ]; then
    log_error "Missing required argument: --kernel <dir>"
    echo ""
    usage
fi

if [ ! -d "$KERNEL_DIR" ]; then
    log_error "Kernel directory does not exist: $KERNEL_DIR"
    exit 1
fi

CONFIG_FILE="${KERNEL_DIR}/.config"

if [ ! -f "$CONFIG_FILE" ]; then
    log_warn ".config not found in $KERNEL_DIR"

    if [ "$DRY_RUN" -eq 1 ]; then
        log_error "Dry run requires an existing .config file."
        exit 1
    fi

    echo ""
    echo "You need a base .config first. Options:"
    echo "  make defconfig        # default config for your arch"
    echo "  make oldconfig        # use existing /boot config"
    echo "  cp /boot/config-\$(uname -r) ${KERNEL_DIR}/.config"
    echo ""
    read -rp "Run 'make defconfig' now? [y/N] " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        make -C "$KERNEL_DIR" defconfig
    else
        exit 1
    fi
fi

echo ""
log_info "Kernel source:  $KERNEL_DIR"
log_info "Config file:    $CONFIG_FILE"
log_info "Profile:        $PROFILE"
log_info "Dry run:        $([ $DRY_RUN -eq 1 ] && echo 'yes' || echo 'no')"
echo ""

if [ "$BACKUP" -eq 1 ] && [ "$DRY_RUN" -eq 0 ]; then
    backup_file="${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$CONFIG_FILE" "$backup_file"
    log_info "Backup saved:   $backup_file"
fi

log_info "Applying debug configs (profile: $PROFILE)..."
echo ""
apply_config "$CONFIG_FILE"

if [ "$DRY_RUN" -eq 0 ]; then
    echo ""
    log_info "Running 'make olddefconfig' to resolve dependencies..."
    make -C "$KERNEL_DIR" olddefconfig
    echo ""
    log_info "Done. You can now build with:"
    echo ""
    echo "  cd $KERNEL_DIR"
    echo "  make -j\$(nproc)"
    echo ""
fi
