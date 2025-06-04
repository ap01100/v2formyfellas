# Инструкция по установке и использованию на Windows

## Требования
- Python 3.6 или выше
- Утилита sing-box (будет установлена автоматически)

## Установка

### Автоматическая установка
1. Откройте командную строку или PowerShell от имени администратора
2. Перейдите в директорию проекта:
   ```
   cd путь\к\v2formyfellas
   ```
3. Запустите скрипт установки:
   ```
   python setup.py
   ```
   Скрипт автоматически:
   - Установит необходимые зависимости Python
   - Проверит наличие sing-box в системе
   - Если sing-box не найден, скачает и установит его в директорию `bin`
   - Обновит конфигурацию с правильным путем к sing-box

### Ручная установка
Если автоматическая установка не сработала, выполните следующие шаги:

1. Установите зависимости:
   ```
   pip install -r requirements.txt
   ```

2. Скачайте sing-box для Windows с [официального репозитория](https://github.com/SagerNet/sing-box/releases)
   - Выберите версию для Windows и вашей архитектуры (обычно `windows-amd64`)
   - Распакуйте архив
   - Поместите `sing-box.exe` в директорию `bin` проекта или в любую директорию, доступную через PATH

3. Отредактируйте файл `filter/config.py`, указав путь к sing-box:
   ```python
   SINGBOX_EXECUTABLE = "путь\\к\\sing-box.exe"  # Используйте двойные обратные слеши в пути
   ```

## Использование

### Базовое тестирование URL
```
python filter\main.py input.txt -o working.txt
```

### Расширенное тестирование
```
python filter\main.py input.txt -o working.txt -a
```

### Комбинированное тестирование
```
python filter\main.py input.txt -o advanced_working.txt --url-then-advanced --temp-file url_working.txt
```

## Решение проблем на Windows

### Проблема: "sing-box не найден"
**Решение**: Укажите полный путь к sing-box.exe с помощью параметра `--singbox-path`:
```
python filter\main.py input.txt -o working.txt --singbox-path "C:\путь\к\sing-box.exe"
```

### Проблема: "Ошибка доступа к порту"
**Решение**: Запустите командную строку или PowerShell от имени администратора.

### Проблема: "Брандмауэр Windows блокирует соединение"
**Решение**: Разрешите sing-box.exe в брандмауэре Windows.

### Проблема: "Антивирус блокирует sing-box"
**Решение**: Добавьте исключение для sing-box.exe в вашем антивирусе.

## Оптимизация производительности на Windows

1. Увеличьте количество рабочих потоков, если у вас многоядерный процессор:
   ```
   python filter\main.py input.txt -o working.txt -w 8
   ```

2. Используйте режим "any" для URL-тестирования, чтобы конфигурация считалась рабочей, если хотя бы один URL доступен:
   ```
   python filter\main.py input.txt -o working.txt --url-mode any
   ```

3. Для больших файлов используйте расширенную дедупликацию:
   ```
   python filter\main.py input.txt -o working.txt --advanced-dedup
   ``` 