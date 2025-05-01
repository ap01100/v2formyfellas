#!/bin/bash

# --- Строгий режим ---
# set -e: Выход немедленно, если команда завершается с ненулевым статусом.
# set -u: Рассматривать неустановленные переменные как ошибку.
# set -o pipefail: Возвращаемый статус конвейера (|) - это статус последней команды,
#                  которая завершилась с ненулевым статусом, или ноль, если все успешно.
set -euo pipefail

# --- Конфигурация ---
# Определяем переменные для URL, имен файлов и путей, чтобы легко их менять.
WORK_DIR="workfiles"
RAW_FILE="${WORK_DIR}/raw.txt"
TEMP_URL_FILE="${WORK_DIR}/url_tested.txt"
TESTED_FILE="tested.txt"

# Источники конфигураций
BARRY_FAR_URL="https://raw.githubusercontent.com/barry-far/V2ray-Configs/refs/heads/main/All_Configs_Sub.txt"
EPODONIOS_URL="https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt"
SOROUSH_URL="https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/subscribe"

# Настройки
SINGBOX_PATH="/usr/local/bin/sing-box"
WORKERS=20
# URL для проверки (по умолчанию)
TEST_URLS=("http://cp.cloudflare.com" "https://gemini.google.com")
URL_MODE="all"  # all - должны работать все URL, any - хотя бы один URL
# Файл с URL (если указан, будет использоваться вместо TEST_URLS)
URLS_FILE="urls_list.txt"  # По умолчанию используем файл urls_list.txt

# --- Функция для отображения справки ---
show_help() {
    echo "Использование: $0 [ОПЦИИ]"
    echo ""
    echo "Скрипт для управления и тестирования V2Ray конфигураций."
    echo ""
    echo "Опции:"
    echo "  -h, --help           Показать эту справку"
    echo "  -u, --url URL        Добавить URL для тестирования (можно использовать несколько раз)"
    echo "  -f, --urls-file FILE Файл со списком URL для тестирования (по умолчанию: $URLS_FILE)"
    echo "  -m, --mode MODE      Установить режим тестирования URL (all или any)"
    echo "                       all: все URL должны работать (по умолчанию)"
    echo "                       any: хотя бы один URL должен работать"
    echo "  -w, --workers N      Установить количество параллельных потоков (по умолчанию: $WORKERS)"
    echo "  -s, --singbox PATH   Указать путь к sing-box (по умолчанию: $SINGBOX_PATH)"
    echo "  --no-urls-file       Не использовать файл с URL, использовать только прямо указанные URL"
    echo ""
    echo "Примеры:"
    echo "  $0                                # Использовать файл urls_list.txt по умолчанию"
    echo "  $0 --url http://cp.cloudflare.com --url https://gemini.google.com --mode any"
    echo "  $0 --urls-file custom_urls.txt --mode all"
    echo "  $0 --workers 20 --singbox /usr/bin/sing-box"
    exit 0
}

# --- Функция для обработки аргументов командной строки ---
parse_args() {
    # Сброс массива URL
    TEST_URLS=()
    # Флаг для отключения использования файла с URL
    local no_urls_file=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                ;;
            -u|--url)
                if [[ -z "${2:-}" ]]; then
                    echo "ОШИБКА: Отсутствует аргумент для параметра --url" >&2
                    exit 1
                fi
                TEST_URLS+=("$2")
                shift 2
                ;;
            -f|--urls-file)
                if [[ -z "${2:-}" ]]; then
                    echo "ОШИБКА: Отсутствует аргумент для параметра --urls-file" >&2
                    exit 1
                fi
                URLS_FILE="$2"
                shift 2
                ;;
            --no-urls-file)
                no_urls_file=true
                URLS_FILE=""
                shift
                ;;
            -m|--mode)
                if [[ -z "${2:-}" ]]; then
                    echo "ОШИБКА: Отсутствует аргумент для параметра --mode" >&2
                    exit 1
                fi
                # Проверка допустимого значения
                if [[ "$2" != "all" && "$2" != "any" ]]; then
                    echo "ОШИБКА: Неверное значение для --mode. Допустимые значения: all, any" >&2
                    exit 1
                fi
                URL_MODE="$2"
                shift 2
                ;;
            -w|--workers)
                if [[ -z "${2:-}" ]]; then
                    echo "ОШИБКА: Отсутствует аргумент для параметра --workers" >&2
                    exit 1
                fi
                # Проверка что значение - число
                if ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    echo "ОШИБКА: Значение --workers должно быть целым числом" >&2
                    exit 1
                fi
                WORKERS="$2"
                shift 2
                ;;
            -s|--singbox)
                if [[ -z "${2:-}" ]]; then
                    echo "ОШИБКА: Отсутствует аргумент для параметра --singbox" >&2
                    exit 1
                fi
                SINGBOX_PATH="$2"
                shift 2
                ;;
            *)
                # Неизвестный параметр
                echo "ОШИБКА: Неизвестный параметр: $1" >&2
                echo "Используйте --help для получения справки" >&2
                exit 1
                ;;
        esac
    done
    
    # Проверка наличия файла с URL
    if [[ -n "$URLS_FILE" && ! -f "$URLS_FILE" ]]; then
        echo "ПРЕДУПРЕЖДЕНИЕ: Файл с URL '$URLS_FILE' не найден." >&2
        
        # Если это был файл по умолчанию, очищаем URLS_FILE
        if [[ "$URLS_FILE" == "urls_list.txt" ]]; then
            echo "Файл по умолчанию urls_list.txt не найден. Будут использованы встроенные URL." >&2
            URLS_FILE=""
        fi
    fi
    
    # Если указан флаг --no-urls-file, убедимся, что URLS_FILE пуст
    if [[ "$no_urls_file" == true ]]; then
        URLS_FILE=""
    fi
    
    # Проверка, что массив URL не пустой и файл URL не указан или не существует
    if [[ ${#TEST_URLS[@]} -eq 0 && -z "$URLS_FILE" ]]; then
        # Установка URL по умолчанию, если не указаны ни URL, ни файл с URL
        TEST_URLS=("http://cp.cloudflare.com" "https://gemini.google.com")
        echo "Используются встроенные URL: ${TEST_URLS[*]}"
    fi
    
    # Вывод информации о параметрах
    echo "Параметры:"
    if [[ -n "$URLS_FILE" ]]; then
        echo "  Файл с URL для тестирования: $URLS_FILE"
    elif [[ ${#TEST_URLS[@]} -gt 0 ]]; then
        echo "  URL для тестирования: ${TEST_URLS[*]}"
    fi
    echo "  Режим проверки URL: $URL_MODE"
    echo "  Количество потоков: $WORKERS"
    echo "  Путь к sing-box: $SINGBOX_PATH"
}

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

    # Начало формирования команды
    local cmd="$PYTHON_CMD $URL_TEST_SCRIPT $input_file -ao $output_file -w $URL_TEST_WORKERS --singbox-path $SINGBOX_PATH"
    
    # Добавляем файл с URL, если он указан
    if [[ -n "$URLS_FILE" ]]; then
        cmd+=" --urls-file $URLS_FILE"
    else
        # Иначе добавляем URL из массива
        for url in "${TEST_URLS[@]}"; do
            cmd+=" -u $url"
        done
    fi
    
    # Добавляем режим проверки URL
    cmd+=" --url-mode $URL_MODE"
    
    # Запускаем Python скрипт
    if eval "$cmd"; then
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

# Обработка аргументов командной строки
parse_args "$@"

# Убедимся, что рабочая директория существует
# mkdir -p: Создает директорию, если она не существует, и не выдает ошибку, если существует.
if ! mkdir -p "$WORK_DIR"; then
    echo "ОШИБКА: Не удалось создать рабочую директорию ${WORK_DIR}" >&2
    exit 1
fi

# Спрашиваем пользователя, нужно ли обновлять конфиги
if ask_user "Обновить конфиги из удаленных источников?"; then
    echo "Пользователь выбрал обновить конфиги."
    # Очищаем файл перед добавлением конфигов
    > "$RAW_FILE"
    
    # Скачиваем оба набора конфигов
    download_and_filter "$BARRY_FAR_URL" "$RAW_FILE" "barry-far"
    download_and_filter "$EPODONIOS_URL" "$RAW_FILE" "epodonios"
    
    # Загрузка и декодирование Base64-закодированных конфигураций
    echo "-> Пытаюсь получить конфиги 'soroushmirzaei' с ${SOROUSH_URL}..."
    if curl -fsSL "$SOROUSH_URL" | base64 -d | grep --color=never '^[A-Za-z]' >> "$RAW_FILE"; then
        echo "   Успешно скачано, декодировано и отфильтровано."
    else
        echo "   ОШИБКА: Не удалось скачать или декодировать конфиги 'soroushmirzaei'." >&2
    fi
else
    echo "Пользователь выбрал не обновлять конфиги. Используются существующие файлы в ${WORK_DIR} (если они есть)."
    # Можно добавить проверку на существование файлов, если не обновляем
    if [[ ! -f "$RAW_FILE" ]]; then
         echo "   ПРЕДУПРЕЖДЕНИЕ: Файл с сырыми конфигами не найден в ${WORK_DIR}. Тестирование может не сработать." >&2
    fi
fi

# Проверка, что файл не пустой
if [ ! -s "$RAW_FILE" ]; then
    echo "Ошибка: Не удалось загрузить конфигурации. Файл пустой."
    exit 1
fi

# Фильтрация (оставляем только строки, начинающиеся с протоколов)
grep -E "^(ss|vmess|trojan|vless)://" "$RAW_FILE" > "${RAW_FILE}.filtered" || true
mv "${RAW_FILE}.filtered" "$RAW_FILE"

TOTAL_CONFIGS=$(wc -l < "$RAW_FILE")
echo "Загружено $TOTAL_CONFIGS конфигураций"

echo
echo "====== Удаление дубликатов ======"
# Промежуточные файлы для дедупликации
DEDUP_STANDARD="${WORK_DIR}/dedup_standard.txt"
DEDUP_ADVANCED="${WORK_DIR}/dedup_advanced.txt"

# Шаг 1: Стандартная дедупликация
echo "Выполняется стандартная дедупликация..."
python3 -c "
import sys
sys.path.append('.')
from utils import remove_duplicates
from main import read_configs_from_file, write_configs_to_file
import logging
logging.basicConfig(level=logging.INFO)

configs = read_configs_from_file('$RAW_FILE')
deduplicated = remove_duplicates(configs)
write_configs_to_file(deduplicated, '$DEDUP_STANDARD')
" || { echo "Ошибка при стандартной дедупликации"; exit 1; }

STANDARD_DEDUP_COUNT=$(wc -l < "$DEDUP_STANDARD")
echo "После стандартной дедупликации осталось $STANDARD_DEDUP_COUNT конфигураций"

# Шаг 2: Расширенная дедупликация
echo "Выполняется расширенная дедупликация..."
python3 -c "
import sys
sys.path.append('.')
from utils import remove_duplicates_advanced
from main import read_configs_from_file, write_configs_to_file
import logging
logging.basicConfig(level=logging.INFO)

configs = read_configs_from_file('$DEDUP_STANDARD')
deduplicated = remove_duplicates_advanced(configs)
write_configs_to_file(deduplicated, '$DEDUP_ADVANCED')
" || { echo "Ошибка при расширенной дедупликации"; exit 1; }

ADVANCED_DEDUP_COUNT=$(wc -l < "$DEDUP_ADVANCED")
echo "После расширенной дедупликации осталось $ADVANCED_DEDUP_COUNT конфигураций"
echo "Дедупликация удалила $((TOTAL_CONFIGS - ADVANCED_DEDUP_COUNT)) дубликатов"

echo
echo "====== Тестирование конфигураций ======"
# Запуск тестирования с помощью main.py

# Запуск тестирования с помощью main.py на дедуплицированных конфигурациях
python3 main.py "$DEDUP_ADVANCED" \
    --url-then-advanced \
    --temp-file "$TEMP_URL_FILE" \
    -o "$TESTED_FILE" \
    --singbox-path "$SINGBOX_PATH" \
    -w "$WORKERS" \
    --advanced-workers "$WORKERS" \
    --no-dedup \
    || { echo "Ошибка при тестировании конфигураций"; exit 1; }

# Результаты
if [ -f "$TESTED_FILE" ]; then
    WORKING_CONFIGS=$(wc -l < "$TESTED_FILE")
    SUCCESS_RATE=$(awk "BEGIN { printf \"%.1f\", ($WORKING_CONFIGS/$TOTAL_CONFIGS)*100 }")
    echo
    echo "====== Результаты ======"
    echo "Из $TOTAL_CONFIGS конфигураций работают: $WORKING_CONFIGS ($SUCCESS_RATE%)"
    echo "Результаты сохранены в $TESTED_FILE"
else
    echo "Предупреждение: Файл с результатами не создан"
fi

echo "Готово!"
exit 0
