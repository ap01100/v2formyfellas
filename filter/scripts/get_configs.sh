#!/bin/bash

# Базовый URL
base_url="https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub"

output_file="barry-far_all.txt"
echo "" > ../workfiles/"$output_file"

# Цикл от 1 до 10
for i in {1..10}
do
  # Формируем полный URL
  url="${base_url}${i}.txt"

  # Скачиваем файл, отбрасываем строки, начинающиеся с #, и записываем в выходной файл
  curl -s "$url" | grep -v '^#' >> ../workfiles/"$output_file"

  # Выводим сообщение о завершении обработки текущего файла
  echo "Processed and saved $url"
done

echo "-----------------------------"
url="https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt"
curl -s "$url" | grep -v '^#' > ../workfiles/epodonios_all.txt

echo "Successfully written epodonios configs"
