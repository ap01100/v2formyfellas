#!/bin/bash

echo "===== v2formyfellas - Скачивание и тестирование прокси ====="
echo

# Создаем директорию для результатов, если её нет
mkdir -p results

# Текущая дата и время для имен файлов
datestamp=$(date +%Y%m%d)
timestamp=$(date +%H%M%S)
filename="configs_${datestamp}_${timestamp}.txt"
output_file="results/${filename}"

echo "Скачивание конфигураций..."
python3 filter/download_configs.py -s filter/sources.txt -o "$output_file"
if [ $? -ne 0 ]; then
    echo "Ошибка при скачивании конфигураций!"
    exit 1
fi

echo
echo "Запуск базового URL-тестирования..."
python3 filter/main.py "$output_file" -o "results/working_url_${datestamp}.txt"
if [ $? -ne 0 ]; then
    echo "Предупреждение: URL-тестирование не нашло рабочих конфигураций."
fi

echo
echo "Запуск расширенного тестирования..."
python3 filter/main.py "results/working_url_${datestamp}.txt" -o "results/working_advanced_${datestamp}.txt" -a
if [ $? -ne 0 ]; then
    echo "Предупреждение: Расширенное тестирование не нашло рабочих конфигураций."
fi

echo
echo "Готово! Результаты сохранены в директории 'results'."
echo "Все конфигурации: $output_file"
echo "Рабочие URL-тест: results/working_url_${datestamp}.txt"
echo "Рабочие расширенный тест: results/working_advanced_${datestamp}.txt"
echo 