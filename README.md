# hh-vault-mcp (v2.1)

> **Universal Resilient Context, TDD Task & Secret Vault for Autonomous AI Agents**  
> *Протокол: Model Context Protocol (MCP) через stdio JSON-RPC.*

`hh-vault-mcp` — это отказоустойчивый сервер Model Context Protocol (MCP), разработанный для автономных ИИ-ассистентов (Google Antigravity, Claude Desktop, Cursor, Cline). Сервер изолирует контекст, задачи, историю решений (ADR) и секреты в локальном SQLite-хранилище проектов, исключая захламление репозиториев временными markdown-файлами и гарантируя соблюдение дисциплины **TDD (Test-Driven Development)**.

---

## Ключевые возможности

### 1. Железный TDD FSM и защита от дедлоков
- Детерминированный конечный автомат задач: `queued` → `red` (падающий тест) → `yellow` (реализация) → `green` (тест прошел с `exit 0`) → `archived`.
- Переход в `green` требует фактического доказательства запуска (`evidence >= 15 символов`).
- **Защита от тупиков (Anti-Deadlock)**:
  - `task_reset`: аварийный сброс застрявшей задачи с записью причины в аудит `task_events`.
  - `task_edit`: изменение формулировки ТЗ и приоритета без костылей в комментариях.
  - `parent_id`: декомпозиция задач на дочерние подзадачи.
  - **Счётчик зацикливания**: после 3 подряд попыток невалидного перехода сервер останавливает агента и требует пересмотра стратегии.
  - **Optimistic Locking**: аргумент `expected_from` защищает от гонок между параллельными субагентами.

### 2. База знаний и FTS5 Поиск
- Хранение архитектурных решений (ADR), сетевых протоколов и заметок.
- Полнотекстовый поиск FTS5 с токенизатором `unicode61`, ранжированием BM25 и двухэтапным поиском (`AND` → `OR`).
- Возврат только компактных сниппетов (минимизация токенов контекстного окна LLM).
- Автоматическое версионирование и история правок в `docs_history`.
- Пагинация больших документов (`offset`, `max_chars`).

### 3. Криптография корпоративного уровня
- Шифрование секретов по стандарту **AES-256-GCM** с AAD (Authenticated Additional Data).
- Привязка AAD к стабильному `project_id` (переименование папки проекта или клон не ломают расшифровку).
- Проверка мастер-ключа через **KCV (Key Check Value)**: отказ при попытке использовать чужой/пересозданный ключ.
- Атомарное создание мастер-ключа с правами `0600` через `fsync`. Запрет автосоздания ключа, если в базе уже есть секреты.

### 4. Отказоустойчивость и Самолечение
- **Разделение Read / Write**: читатели работают через моментальный снимок WAL (`PRAGMA query_only = ON`) и никогда не блокируют пишущих агентов.
- **Внешние бэкапы**: резервные копии сохраняются в `~/.local/share/hh-vault/...`, что защищает их от удаления при `git clean -fdx`.
- **Самодиагностика (`vault_doctor`)**: проверка целостности SQLite, сверка внешнего содержимого FTS5 с таблицей документов (`rank=1`), валидация KCV и страниц WAL.
- **Самолечение (`vault_repair`)**: восстановление из последней валидной копии (`restore_latest`) с помещением битой базы в карантин (`.corrupt-<ts>`), обрезка WAL (`checkpoint_wal`), аварийный текстовый JSON-дамп (`dump_json`).
- **Неблокирующий Event Loop**: все синхронные операции SQLite вынесены в пул потоков через `anyio.to_thread.run_sync`.

---

## Архитектура хранилища

Сервер разворачивается **глобально** в окружении ассистента, а данные хранит **локально** в корне каждого проекта:

```
my-project/
├── .vault/
│   ├── .gitignore       # Исключает vault.db из Git-индекса
│   └── vault.db         # SQLite БД (WAL, FTS5, AES-секреты)
├── ... код проекта
```

Резервные копии и ключи хранятся в защищённых пользовательских каталогах:
- `~/.hh_vault.key` — локальный 256-битный мастер-ключ (права `0600`).
- `~/.local/share/hh-vault/<project-hash>/backups/` — ротация последних 10 валидных бэкапов базы.

---

## Установка

Требуется **Python 3.10+**.

```bash
# Клонирование репозитория
git clone https://github.com/leosiso/mcp.git ~/.local/share/hh-vault-mcp
cd ~/.local/share/hh-vault-mcp

# Создание виртуального окружения
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

# Прогон встроенных стресс-тестов
./venv/bin/python server.py --test
```

---

## Подключение к AI-агентам

### 1. Google Antigravity (`~/.gemini/config/mcp_config.json`)
```json
{
  "mcpServers": {
    "hh-vault": {
      "command": "/home/USER/.local/share/hh-vault-mcp/venv/bin/python",
      "args": [
        "/home/USER/.local/share/hh-vault-mcp/server.py"
      ]
    }
  }
}
```

### 2. Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "hh-vault": {
      "command": "/path/to/venv/bin/python",
      "args": ["/path/to/server.py"]
    }
  }
}
```

### 3. Cursor / VSCode / Cline
Добавьте сервер с типом команды `stdio`, указав путь к Python-интерпретатору окружения и `server.py`.

---

## Набор инструментов (Tools API)

### Задачи (TDD FSM)
| Инструмент | Аргументы | Описание |
| :--- | :--- | :--- |
| `task_create` | `title, description, priority, tags, parent_id` | Создаёт задачу в статусе `queued`. |
| `task_update` | `task_id, status, evidence, note, expected_from` | Переводит статус задачи. Для `green` обязателен факт теста (`evidence`). |
| `task_reset` | `task_id, reason, target_status, expected_from` | Аварийный сброс задачи в `queued` или `archived` с записью в аудит. |
| `task_edit` | `task_id, reason, title, description, priority, tags` | Корректирует ТЗ задачи при смене требований. |
| `task_get` | `task_id` | Возвращает данные задачи и историю последних 10 событий. |
| `task_list` | `status, limit` | Возвращает список активных задач, отсортированных по приоритету. |

### База знаний (Docs & ADR)
| Инструмент | Аргументы | Описание |
| :--- | :--- | :--- |
| `doc_set` | `slug, title, category, content, tags, expected_updated_at` | Сохраняет или обновляет документ с версионированием. |
| `doc_search`| `query, limit` | Полнотекстовый поиск FTS5 (BM25 + сниппеты). |
| `doc_get` | `slug, offset, max_chars` | Чтение документа с пагинацией. |
| `doc_list` | `category, limit` | Каталог документов по категориям. |
| `doc_delete`| `slug` | Удаление документа (копия остаётся в `docs_history`). |

### Секреты (AES-256-GCM)
| Инструмент | Аргументы | Описание |
| :--- | :--- | :--- |
| `secret_set` | `key, value, description` | Шифрует и сохраняет секрет. |
| `secret_get` | `key` | Расшифровывает значение секрета. |
| `secret_list` | — | Список доступных ключей (без раскрытия значений). |
| `secret_delete`| `key` | Удаляет секрет. |

### Диагностика и Самолечение
| Инструмент | Аргументы | Описание |
| :--- | :--- | :--- |
| `vault_summary` | — | Сводка состояния проекта (кол-во задач, документов, секретов). |
| `vault_doctor` | — | Полный аудит целостности (Quick check, FTS5 vs Docs, KCV, WAL). |
| `vault_repair` | `action` (`rebuild_fts`, `checkpoint_wal`, `backup`, `restore_latest`, `dump_json`) | Самолечение базы при сбоях. |

---

## Лицензия

MIT License (c) 2026 Leo Siso.
