#!/usr/bin/env python3
import json
import os
from filter.parsers import convert_to_singbox_config

# Создаем директорию для временных файлов, если она не существует
os.makedirs("workfiles", exist_ok=True)

# Тестовая VMess конфигурация
vmess_config = 'vmess://eyJhZGQiOiJlbG1hLm5zLmNsb3VkZmxhcmUuY29tIiwiYWlkIjoiMCIsImhvc3QiOiJlbG1hLm5zLmNsb3VkZmxhcmUuY29tIiwiaWQiOiI4MjNjMzFkYS03MDFmLTQ4M2QtODI5Mi0yMDk4YzEyMWNhYTQiLCJuZXQiOiJ3cyIsInBhdGgiOiIvIiwicG9ydCI6IjgwIiwicHMiOiJ0ZXN0IFZNLVdTLU5BIiwic2N5IjoiYXV0byIsInRscyI6IiIsInR5cGUiOiIiLCJ2IjoiMiJ9'

# Преобразуем в конфигурацию sing-box
config = convert_to_singbox_config(vmess_config, 10000)

# Сохраняем в файл
with open("workfiles/test_config.json", "w") as f:
    json.dump(config, f, indent=2)

print("Конфигурация сохранена в workfiles/test_config.json")
print("\nСодержимое конфигурации:")
config_str = json.dumps(config, indent=2)
print(config_str)

# Проверяем все ключи в конфигурации
print("\nПроверка структуры конфигурации:")
print(f"Ключи верхнего уровня: {list(config.keys())}")
print(f"DNS настройки: {config.get('dns', {})}")
print(f"Route настройки: {config.get('route', {})}") 