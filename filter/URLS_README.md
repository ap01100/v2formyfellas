# Проверка прокси-конфигураций на нескольких URL

## Использование файла с URL

Вы можете создать файл со списком URL, которые будут использоваться для проверки прокси-конфигураций. Это удобно, когда нужно регулярно проверять конфигурации на одном и том же наборе URL.

### Формат файла

В файле с URL каждый адрес должен быть на отдельной строке. Пустые строки и строки, начинающиеся с `#`, игнорируются.

Пример файла `urls_list.txt`:

```
# Основные URL для проверки
http://cp.cloudflare.com
https://gemini.google.com

# Другие URL
https://www.google.com
https://www.bing.com
```

### Использование в командной строке

Для использования файла с URL в командной строке используйте параметр `--urls-file`:

```bash
python main.py input.txt -o working.txt --urls-file urls_list.txt
```

Вы также можете указать режим проверки:

```bash
# Все URL должны работать
python main.py input.txt -o working.txt --urls-file urls_list.txt --url-mode all

# Хотя бы один URL должен работать
python main.py input.txt -o working.txt --urls-file urls_list.txt --url-mode any
```

### Использование в скрипте run_test.sh

Если вы используете скрипт `run_test.sh`, вы можете указать файл с URL через параметр `--urls-file`:

```bash
./run_test.sh --urls-file urls_list.txt
```

Или указать режим проверки:

```bash
./run_test.sh --urls-file urls_list.txt --mode any
```

## Рекомендации по выбору URL

При составлении списка URL рекомендуется включить:

1. **Базовые URL** - простые сайты для проверки работоспособности прокси
2. **URL разных регионов** - сайты из разных географических регионов
3. **URL с геоограничениями** - для проверки обхода региональных блокировок
4. **URL различных типов** - HTTP, HTTPS, различные порты

## Пример готового списка URL

В файле `urls_list.txt` в директории `filter` уже подготовлен список URL для тестирования. Вы можете использовать его как основу и добавить свои URL.

```bash
# Просмотр содержимого примера
cat filter/urls_list.txt

# Использование примера
python3 filter/main.py configs.txt -o working.txt --urls-file filter/urls_list.txt
``` 