#!/bin/bash
set -euo pipefail

POLKIT_RULE="/etc/polkit-1/rules.d/99-panzir-test.rules"
ORIG_AUTOMOUNT=""
USER_NAME=$(id -un)

# T-3 (btrfs) ищет каталог в PANZIR_IT_DIR. Если переменная не задана, а $HOME
# лежит на btrfs — используем его, чтобы тест бежал из коробки на Fedora.
if [[ -z "${PANZIR_IT_DIR:-}" ]] && command -v stat >/dev/null; then
    if [[ "$(stat -f -c %T "$HOME")" == "btrfs" ]]; then
        export PANZIR_IT_DIR="$HOME"
    fi
fi

# Проверяет, что путь — наш тестовый контейнер (не продуктовый vault).
# Разрешённые места: /tmp/.tmpXXXXX/ или $PANZIR_IT_DIR/.
# Разрешённое имя: panzir-tN.vault или panzir-tN-PID.vault (T-3).
is_our_test_container() {
    local path="$1"
    local dir base
    dir=$(dirname "$path")
    base=$(basename "$path")

    local in_tmp=false
    if [[ "$dir" == /tmp || "$dir" == /tmp/* ]]; then
        in_tmp=true
    fi
    local in_it_dir=false
    if [[ -n "${PANZIR_IT_DIR:-}" && ( "$dir" == "$PANZIR_IT_DIR" || "$dir" == "$PANZIR_IT_DIR"/* ) ]]; then
        in_it_dir=true
    fi

    if [[ "$in_tmp" == false && "$in_it_dir" == false ]]; then
        return 1
    fi
    [[ "$base" =~ ^panzir-t[0-9]+(-[0-9]+)?\.vault$ ]]
}

sweep_panzir() {
    if ! command -v udisksctl >/dev/null; then
        return
    fi

    # 1. Найти наши loop'ы по backing_file и снять их.
    local changed=true
    local attempt=0
    while [[ "$changed" == true && $attempt -lt 10 ]]; do
        changed=false
        for backing in /sys/block/loop*/loop/backing_file; do
            if [[ ! -f "$backing" ]]; then
                continue
            fi
            local vault_path=""
            vault_path=$(cat "$backing" 2>/dev/null | sed 's/ (deleted)$//' || true)
            if [[ -z "$vault_path" ]] || ! is_our_test_container "$vault_path"; then
                continue
            fi

            local loop_name loop_dev
            loop_name=$(basename "$(dirname "$(dirname "$backing")")")
            loop_dev="/dev/$loop_name"

            # Сначала размонтировать детей (dm-crypt / точка монтирования), не сам loop.
            for child in $(lsblk -nro PATH "$loop_dev" | tail -n +2); do
                udisksctl unmount -b "$child" --no-user-interaction || true
            done

            udisksctl lock -b "$loop_dev" --no-user-interaction || true
            udisksctl loop-delete -b "$loop_dev" --no-user-interaction || true

            # Удаляем файл по пути из backing_file, если он ещё не удалён.
            if [[ -f "$vault_path" ]]; then
                rm -f "$vault_path" || true
            fi

            changed=true
        done
        ((attempt++)) || true
        sleep 1
    done

    # 2. Убрать оставшиеся .vault-файлы в разрешённых каталогах.
    find /tmp -maxdepth 2 -name 'panzir-t[0-9]*.vault' -delete 2>/dev/null || true
    if [[ -n "${PANZIR_IT_DIR:-}" ]]; then
        find "$PANZIR_IT_DIR" -maxdepth 1 -name 'panzir-t[0-9]*.vault' -delete 2>/dev/null || true
    fi
}

cleanup() {
    sweep_panzir

    # Восстановление настроек. Свип выполнен первым: loop-delete после Lock
    # работает только пока polkit-правило даёт нашему uid право на операции
    # с loop-устройством.
    if sudo test -f "$POLKIT_RULE"; then
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
# Метки ФС тестов бывают двух видов: 'panzir-tN' (create_it) и 'tN'
# (lifecycle_it — там метка ещё и строит путь симлинка ~/panzir-<метка>,
# поэтому префикс в ней был бы задвоен). Страж обязан видеть оба, иначе он
# ослеп ровно на новый сьют (М-13 ревью раунда 1).
if findmnt -t ext4 -o LABEL | grep -qE '^(panzir-t|t)[0-9]+'; then
    echo "ERROR: leftover panzir mounts" >&2
    exit 1
fi
if find /tmp -maxdepth 2 -name 'panzir-*.vault' -print -quit 2>/dev/null | grep -q .; then
    echo "ERROR: leftover panzir vault files" >&2
    exit 1
fi

# 4. Run tests.
# Необязательный аргумент — фильтр имени теста. Нужен для мутаций: инвариант
# проверяется прогоном ОДНОГО теста в подготовленной среде, а не всего набора
# (иначе каждая мутация стоит трёх сьютов). Без аргумента поведение прежнее.
FILTER="${1:-}"

PANZIR_IT=1 cargo test -p panzir-core --test create_it -- --ignored $FILTER
PANZIR_IT=1 cargo test -p panzir-core --test pr2_it -- --ignored $FILTER
PANZIR_IT=1 cargo test -p panzir-core --test lifecycle_it -- --ignored $FILTER

# 5. Post-run sanity check (same as pre-flight).
if command -v losetup >/dev/null && [[ -n $(losetup -a) ]]; then
    echo "ERROR: tests left behind loop devices" >&2
    exit 1
fi
if findmnt -t ext4 -o LABEL | grep -qE '^(panzir-t|t)[0-9]+'; then
    echo "ERROR: tests left behind panzir mounts" >&2
    exit 1
fi
if find /tmp -maxdepth 2 -name 'panzir-*.vault' -print -quit 2>/dev/null | grep -q .; then
    echo "ERROR: tests left behind panzir vault files" >&2
    exit 1
fi
