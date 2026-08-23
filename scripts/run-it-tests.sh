#!/bin/bash
set -euo pipefail

POLKIT_RULE="/etc/polkit-1/rules.d/99-panzir-test.rules"
ORIG_AUTOMOUNT=""
USER_NAME=$(id -un)

sweep_panzir() {
    if ! command -v udisksctl >/dev/null; then
        return
    fi

    # 1. Найти наши loop'ы по backing_file и снять их.
    local changed=true
    local attempt=0
    while [[ "$changed" == true && $attempt -lt 5 ]]; do
        changed=false
        for backing in /sys/block/loop*/loop/backing_file; do
            if [[ -f "$backing" ]] && grep -qE "panzir-.*\.vault" "$backing" 2>/dev/null; then
                loop_name=$(basename "$(dirname "$(dirname "$backing")")")
                loop_dev="/dev/$loop_name"

                # Запоминаем путь к файлу контейнера до разрушения loop.
                local vault_path=""
                vault_path=$(cat "$backing" 2>/dev/null | sed 's/ (deleted)$//')

                # Сначала размонтировать детей (dm-crypt / точка монтирования), не сам loop.
                for child in $(lsblk -nro PATH "$loop_dev" | tail -n +2); do
                    udisksctl unmount -b "$child" --no-user-interaction || true
                done

                udisksctl lock -b "$loop_dev" --no-user-interaction || true
                udisksctl loop-delete -b "$loop_dev" --no-user-interaction || true

                # Удаляем файл по пути из backing_file, если он ещё не удалён.
                if [[ -n "$vault_path" && -f "$vault_path" ]]; then
                    rm -f "$vault_path" || true
                fi

                changed=true
            fi
        done
        ((attempt++)) || true
        sleep 0.5
    done

    # 2. Убрать оставшиеся .vault-файлы (tempfile создаёт /tmp/.tmpXXXXX/panzir-*.vault).
    find /tmp -maxdepth 2 -name 'panzir-*.vault' -delete 2>/dev/null || true
    find "$HOME" -maxdepth 1 -name 'panzir-*' -type l -delete 2>/dev/null || true
}

cleanup() {
    sweep_panzir

    # Восстановление настроек.
    if [[ -f "$POLKIT_RULE" ]] && grep -q "panzir-test-rule" "$POLKIT_RULE"; then
        sudo rm -f "$POLKIT_RULE"
    fi
    if [[ -n "$ORIG_AUTOMOUNT" ]] && command -v gsettings >/dev/null; then
        gsettings set org.gnome.desktop.media-handling automount "$ORIG_AUTOMOUNT" || true
    fi
}
trap cleanup EXIT

# 1. Polkit rule if missing.
if [[ ! -f "$POLKIT_RULE" ]]; then
    sudo tee "$POLKIT_RULE" >/dev/null <<EOF
/* panzir-test-rule: auto-managed by scripts/run-it-tests.sh */
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.freedesktop.udisks2.") === 0 &&
        subject.user === "$USER_NAME") {
        return polkit.Result.YES;
    }
});
EOF
fi

# 2. Disable GNOME automount.
if command -v gsettings >/dev/null; then
    ORIG_AUTOMOUNT=$(gsettings get org.gnome.desktop.media-handling automount)
    gsettings set org.gnome.desktop.media-handling automount false
fi

# 3. Pre-flight sanity check.
# Trade-off: проверка общемашинная — любой сторонний loop сделает прогон красным.
# Это приемлемо для локальной рабочей машины; в CI скрипт не используется.
if command -v losetup >/dev/null && [[ -n $(losetup -a) ]]; then
    echo "ERROR: leftover loop devices" >&2
    exit 1
fi
if findmnt -t ext4 -o LABEL | grep -q '^panzir-'; then
    echo "ERROR: leftover panzir mounts" >&2
    exit 1
fi
if find /tmp -maxdepth 2 -name 'panzir-*.vault' -print -quit 2>/dev/null | grep -q .; then
    echo "ERROR: leftover panzir vault files" >&2
    exit 1
fi

# 4. Run tests.
PANZIR_IT=1 cargo test -p panzir-core --test create_it -- --ignored

# 5. Post-run sanity check (same as pre-flight).
if command -v losetup >/dev/null && [[ -n $(losetup -a) ]]; then
    echo "ERROR: tests left behind loop devices" >&2
    exit 1
fi
if findmnt -t ext4 -o LABEL | grep -q '^panzir-'; then
    echo "ERROR: tests left behind panzir mounts" >&2
    exit 1
fi
if find /tmp -maxdepth 2 -name 'panzir-*.vault' -print -quit 2>/dev/null | grep -q .; then
    echo "ERROR: tests left behind panzir vault files" >&2
    exit 1
fi
