#!/bin/bash

# --- Строгий режим ---
# set -e: Выход немедленно, если команда завершается с ненулевым статусом.
# set -u: Рассматривать неустановленные переменные как ошибку.
# set -o pipefail: Возвращаемый статус конвейера (|) - это статус последней команды,
#                  которая завершилась с ненулевым статусом, или ноль, если все успешно.
set -euo pipefail

# --- Конфигурация ---
# Определяем переменные для URL, имен файлов и путей, чтобы легко их менять.
readonly WORK_DIR="workfiles"         # Рабочая директория для временных файлов
readonly DEST_DIR=".."                # Директория назначения для финальных конфигов

# Источники конфигураций
declare -A SOURCES=(
    ["epodonios"]="https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt"
    ["barry-far"]="https://raw.githubusercontent.com/barry-far/V2ray-Configs/refs/heads/main/All_Configs_Sub.txt"
)

# Имена файлов (исходные, протестированные, финальные)
readonly EPODONIOS_RAW_FILE="${WORK_DIR}/epodonios_all_raw.txt"
readonly EPODONIOS_TESTED_FILE="${WORK_DIR}/epodonios_all_tested.txt"
readonly EPODONIOS_DEST_FILE="${DEST_DIR}/epodonios_all.txt"

readonly BARRYFAR_RAW_FILE="${WORK_DIR}/barry-far_all_raw.txt"
readonly BARRYFAR_TESTED_FILE="${WORK_DIR}/barry-far_all_tested.txt"
readonly BARRYFAR_DEST_FILE="${DEST_DIR}/configs.txt" # Имя файла назначения для barry-far

# Настройки для теста URL
readonly PYTHON_CMD="python3"
readonly URL_TEST_SCRIPT="url_test.py"
readonly SINGBOX_PATH="/usr/local/bin/sing-box"
readonly URL_TEST_WORKERS="10"

# --- Функции ---

# Функция для вывода сообщения и получения ответа пользователя (yes/no/да/нет).
# Возвращает 0 для "да", 1 для "нет".
ask_user() {
    local prompt="$1"
    local answer
    while true; do
        # Запрашиваем ввод у пользователя
        read -p "$prompt (yes/no/да/нет): " answer
        # Приводим ответ к нижнему регистру (требуется Bash 4+)
        # Если используется более старая версия Bash, замените на:
        # answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]')
        answer="${answer,,}"

        case "$answer" in
            y|д|да|yes) return 0 ;; # Успех (да)
            n|н|нет|no) return 1 ;; # Неудача (нет)
            *) echo "Пожалуйста, ответьте yes/no (да/нет)." ;; # Неверный ввод
        esac
    done
}

# Функция для скачивания и фильтрации конфигураций.
# $1: URL источника
# $2: Файл для сохранения сырых данных
# $3: Имя источника (для логов)
download_and_filter() {
    local url="$1"
    local output_file="$2"
    local source_name="$3"

    echo "-> Пытаюсь получить конфиги '${source_name}' с ${url}..."
    # curl: -s (тихий режим), -L (следовать редиректам), -f (завершиться с ошибкой при ошибках HTTP)
    # grep '^[A-Za-z]': Фильтрует строки, начинающиеся с буквы (как в оригинале)
    # --color=never: Убедиться, что grep не добавляет цветовые коды
    if curl -fsSL "$url" | grep --color=never '^[A-Za-z]' > "$output_file"; then
        echo "   Успешно скачано и отфильтровано в ${output_file}."
    else
        # Выводим ошибку в stderr
        echo "   ОШИБКА: Не удалось скачать или отфильтровать конфиги '${source_name}'." >&2
        # Можно добавить 'exit 1', если скачивание критично
        return 1 # Возвращаем ошибку
    fi
    return 0 # Возвращаем успех
}

# Функция для запуска теста URL с помощью Python скрипта.
# $1: Входной файл (сырые конфиги)
# $2: Выходной файл (протестированные конфиги)
# $3: Имя источника (для логов)
run_test() {
    local input_file="$1"
    local output_file="$2"
    local source_name="$3"

    # Проверяем, существует ли входной файл
    if [[ ! -f "$input_file" ]]; then
        echo "-> ОШИБКА: Входной файл для теста '${input_file}' не найден. Пропускаю тест для '${source_name}'." >&2
        return 1 # Возвращаем ошибку
    fi

    echo "---------------------------------------------"
    echo "-> Запускаю тесты для конфигов '${source_name}' (файл: ${input_file})..."

    # Запускаем Python скрипт
    # Важно: Оригинальный скрипт использовал '-ao "$input_file"', что перезаписывало входной файл.
    #          Эта версия записывает результат в отдельный файл ($output_file).
    if "$PYTHON_CMD" "$URL_TEST_SCRIPT" "$input_file" -ao "$output_file" -w "$URL_TEST_WORKERS" --singbox-path "$SINGBOX_PATH"; then
        echo "   Успешно протестировано. Результат в ${output_file}."
    else
        echo "   ОШИБКА: Не удалось выполнить тест для '${source_name}'." >&2
        # Можно добавить 'exit 1', если тест критичен
        return 1 # Возвращаем ошибку
    fi
    return 0 # Возвращаем успех
}

# Функция для копирования протестированных конфигов в директорию назначения.
# $1: Исходный файл (протестированные конфиги)
# $2: Файл назначения
# $3: Имя источника (для логов)
move_configs() {
    local source_file="$1"
    local destination_file="$2"
    local source_name="$3"

    # Проверяем, существует ли исходный файл
    if [[ ! -f "$source_file" ]]; then
        echo "-> ОШИБКА: Исходный файл '${source_file}' не найден. Не могу переместить конфиги '${source_name}'." >&2
        return 1
    fi

    echo "-> Копирую протестированные конфиги '${source_name}' из ${source_file} в ${destination_file}..."
    # Используем cp вместо 'cat >', это стандартный способ копирования файлов.
    if cp "$source_file" "$destination_file"; then
        echo "   Успешно скопировано."
    else
        echo "   ОШИБКА: Не удалось скопировать '${source_name}' в ${destination_file}." >&2
        return 1
    fi
    return 0
}

# --- Основная логика скрипта ---

echo "Запуск скрипта управления V2Ray конфигами..."

# Убедимся, что рабочая директория существует
# mkdir -p: Создает директорию, если она не существует, и не выдает ошибку, если существует.
if ! mkdir -p "$WORK_DIR"; then
    echo "ОШИБКА: Не удалось создать рабочую директорию ${WORK_DIR}" >&2
    exit 1
fi

# Спрашиваем пользователя, нужно ли обновлять конфиги
if ask_user "Обновить конфиги из удаленных источников?"; then
    echo "Пользователь выбрал обновить конфиги."
    # Скачиваем оба набора конфигов
    download_and_filter "${SOURCES[epodonios]}" "$EPODONIOS_RAW_FILE" "epodonios"
    download_and_filter "${SOURCES[barry-far]}" "$BARRYFAR_RAW_FILE" "barry-far"
else
    echo "Пользователь выбрал не обновлять конфиги. Используются существующие файлы в ${WORK_DIR} (если они есть)."
    # Можно добавить проверку на существование файлов, если не обновляем
    if [[ ! -f "$EPODONIOS_RAW_FILE" || ! -f "$BARRYFAR_RAW_FILE" ]]; then
         echo "   ПРЕДУПРЕЖДЕНИЕ: Один или оба файла с сырыми конфигами не найдены в ${WORK_DIR}. Тестирование может не сработать." >&2
    fi
fi

# Запускаем тесты для обоих наборов конфигов (используем _raw файлы как входные, _tested как выходные)
run_test "$BARRYFAR_RAW_FILE" "$BARRYFAR_TESTED_FILE" "barry-far"
run_test "$EPODONIOS_RAW_FILE" "$EPODONIOS_TESTED_FILE" "epodonios"

echo "---------------------------------------------"

# Спрашиваем, нужно ли перемещать (копировать) протестированные конфиги
if ask_user "Переместить (скопировать) протестированные конфиги в публичную директорию (${DEST_DIR})?"; then
    echo "Пользователь согласился переместить файлы."
    move_configs "$BARRYFAR_TESTED_FILE" "$BARRYFAR_DEST_FILE" "barry-far"
    move_configs "$EPODONIOS_TESTED_FILE" "$EPODONIOS_DEST_FILE" "epodonios"
else
    echo "Пользователь отказался. Протестированные файлы остаются в ${WORK_DIR} (${BARRYFAR_TESTED_FILE}, ${EPODONIOS_TESTED_FILE})."
fi

echo "---------------------------------------------"
echo "Скрипт завершен."

exit 0 # Успешное завершение
