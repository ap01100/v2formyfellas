#!/bin/bash

# Базовый URL
base_url="https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub"

# Цикл от 1 до 10
for i in {1..10}
do
  # Формируем полный URL
  url="${base_url}${i}.txt"

  # Формируем имя выходного файла
  output_file="configs${i}.txt"

  # Скачиваем файл, отбрасываем строки, начинающиеся с #, и записываем в выходной файл
  curl -s "$url" | grep -v '^#' > ../input/"$output_file"

  # Выводим сообщение о завершении обработки текущего файла
  echo "Processed $url and saved to $output_file"
done
