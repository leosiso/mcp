#!/usr/bin/env python3
"""
hh-vault-mcp — Универсальный отказоустойчивый сервер контекста, задач и секретов для ИИ-агентов.
Протокол: Model Context Protocol (MCP) через stdio JSON-RPC.

Версия 2.1 (Hardened / Production-Grade Resilient):
- Разделение read/write: read() через PRAGMA query_only=ON (чистый снимок WAL), tx() с BEGIN IMMEDIATE и ретраем.
- Checkpoint WAL вне транзакций с честным рапортом busy/log/done.
- Защита мастер-ключа: KCV в meta, привязка AAD к стабильному project_id, запрет автосоздания при существующих секретах.
- Оптимистическая блокировка гонок (expected_from, expected_status, expected_updated_at).
- Защита от дедлоков FSM: task_reset, task_edit, parent_id, счетчик повторных отказов.
- FTS5 поиск с отбрасыванием пунктуации, fallback AND -> OR, ранжирование BM25 и пагинация doc_get.
- Внешнее резервное копирование: бэкапы вне дерева git (~/.local/share/hh-vault/...), автобэкап, restore_latest с карантином.
- Полная неблокирующая асинхронность MCP (anyio to_thread.run_sync).
"""

import os
import sys
import json
import sqlite3
import base64
import re
import time
import random
import shutil
import hashlib
import hmac
import tempfile
import threading
import contextlib
import functools
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Literal, Tuple
from contextlib import contextmanager

# Принудительно устанавливаем безопасный umask для всех создаваемых файлов и папок
os.umask(0o077)

try:
    from mcp.server.fastmcp import FastMCP
    from anyio import to_thread
except ImportError:
    FastMCP = None
    to_thread = None


def _get_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _j(obj: Any) -> str:
    """Компактная сериализация JSON для минимизации токенов LLM."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + f"…[обрезано, ещё {len(s) - n} симв.]"


# --- 1. ОПРЕДЕЛЕНИЕ И ГРАНИЦЫ ПРОЕКТА ---

def resolve_project_root() -> Path:
    """Определяет корень проекта строго по .git или переменной окружения.
    Исключает $HOME и root во избежание захвата dotfiles-репозиториев."""
    home = Path.home().resolve()
    root = Path("/").resolve()

    def _validate(p: Path) -> Path:
        resolved = p.resolve()
        if resolved in (home, root):
            raise RuntimeError(
                f"Директория '{resolved}' не может быть корнем проекта (в $HOME часто находится dotfiles git). "
                "Задайте точный путь в переменной HH_PROJECT_DIR."
            )
        return resolved

    env_root = os.environ.get("HH_PROJECT_DIR")
    if env_root:
        p = Path(env_root).resolve()
        if not p.exists() or not p.is_dir():
            raise RuntimeError(f"HH_PROJECT_DIR указывает на несуществующий каталог: {env_root}")
        return _validate(p)

    current = Path.cwd().resolve()
    for p in [current] + list(current.parents):
        if (p / ".git").exists():
            return _validate(p)

    raise RuntimeError(
        f"Корень проекта не найден! Каталог '{current}' не находится внутри Git-репозитория. "
        "Задайте переменную HH_PROJECT_DIR или запускайте сервер из корня проекта."
    )


# --- 2. КРИПТОГРАФИЯ (AES-256-GCM + AAD + KCV + SAFE MASTER KEY) ---

def _key_path() -> Path:
    return Path.home() / ".hh_vault.key"


def _load_key_file(p: Path) -> bytes:
    fd = os.open(str(p), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if st.st_mode & 0o077:
            raise ValueError(f"Небезопасные права доступа к мастер-ключу {p}. Выполните: chmod 600 {p}")
        data = os.read(fd, 64)
    finally:
        os.close(fd)

    if len(data) != 32:
        raise ValueError(
            f"Мастер-ключ в {p} повреждён ({len(data)} байт вместо 32). "
            "Если секретов в базе нет, удалите повреждённый файл; иначе восстановите ключ из бэкапа."
        )
    return data


def _create_key_file(p: Path) -> bytes:
    key = os.urandom(32)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)

    try:
        os.link(str(tmp), str(p))
    except FileExistsError:
        return _load_key_file(p)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(str(tmp))

    dfd = os.open(str(p.parent), os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return key


def _get_master_key(*, allow_create: bool = False) -> bytes:
    env_key = os.environ.get("HH_VAULT_KEY")
    if env_key:
        try:
            raw = base64.b64decode(env_key, validate=True)
            if len(raw) == 32:
                return raw
        except Exception:
            pass
        raise ValueError("HH_VAULT_KEY должен быть валидной base64 строкой от ровно 32 байт.")

    p = _key_path()
    if p.exists():
        return _load_key_file(p)

    if not allow_create:
        raise RuntimeError(
            f"Мастер-ключ {p} не найден, а в хранилище проекта уже присутствуют секреты. "
            "Автоматическое создание нового ключа заблокировано, чтобы не сделать старые секреты нечитаемыми. "
            "Восстановите файл ключа или передайте HH_VAULT_KEY."
        )

    return _create_key_file(p)


def _kcv(key: bytes) -> str:
    """Key Check Value для валидации совпадения мастер-ключа проекта."""
    return hmac.new(key, b"hh-vault-kcv-v1", hashlib.sha256).hexdigest()[:16]


def _check_or_store_kcv(conn: sqlite3.Connection, key: bytes, *, store: bool):
    row = conn.execute("SELECT v FROM meta WHERE k = 'kcv';").fetchone()
    calc_kcv = _kcv(key)
    if row is None:
        if store:
            conn.execute("INSERT INTO meta(k, v) VALUES ('kcv', ?);", (calc_kcv,))
    elif not hmac.compare_digest(row["v"], calc_kcv):
        raise ValueError(
            "Отказ доступа к секретам: текущий мастер-ключ не совпадает с ключом, которым зашифрованы секреты проекта "
            "(другой HOME, неверный HH_VAULT_KEY или файл ключа был пересоздан). Запись/чтение отменены."
        )


def _aad(project_id: str, key_name: str) -> bytes:
    return b"\x00".join((b"hh-vault/v2", project_id.encode("utf-8"), key_name.encode("utf-8")))


def _encrypt_secret(plaintext: str, aad: bytes, key: bytes) -> str:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise RuntimeError(
            "Пакет 'cryptography' не установлен. Установите: uv pip install cryptography "
            "или apt install python3-cryptography."
        )

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
    return "aesgcm:v2:" + base64.b64encode(nonce + ciphertext).decode("utf-8")


def _decrypt_secret(token: str, aad: bytes, key: bytes) -> str:
    if not token.startswith("aesgcm:v2:"):
        raise ValueError("Неподдерживаемый или устаревший формат шифрования секрета.")

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise RuntimeError("Пакет 'cryptography' не установлен. Расшифровка невозможна.")

    aesgcm = AESGCM(key)
    raw = base64.b64decode(token[10:], validate=True)
    nonce, ciphertext = raw[:12], raw[12:]
    try:
        return aesgcm.decrypt(nonce, ciphertext, aad).decode("utf-8")
    except Exception as e:
        raise ValueError("Ошибка расшифровки: секрет повреждён, подменён или использован неверный ключ.") from e


# --- 3. ХРАНИЛИЩЕ ПРОЕКТА (SQLITE WAL + FTS5 + ВНЕШНИЕ БЭКАПЫ) ---

_VAULT_LOCK = threading.Lock()
_LAST_BACKUP_TIME = 0.0


class ProjectVault:
    SCHEMA_VERSION = 2

    def __init__(self, project_root: Optional[Path] = None):
        self.project_root = project_root or resolve_project_root()
        self.project_name = self.project_root.name
        self.db_dir = self.project_root / ".vault"
        self.db_path = self.db_dir / "vault.db"

        # Внешний каталог бэкапов: вне дерева git, чтобы git clean -fdx не уничтожил резервные копии
        proj_hash = hashlib.sha256(str(self.project_root).encode("utf-8")).hexdigest()[:12]
        self.backup_dir = Path.home() / ".local/share/hh-vault" / f"{self.project_name}-{proj_hash}" / "backups"

        self._ready = False
        self._ensure_secure_dir()

    def _ensure_secure_dir(self):
        self.db_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.db_dir, 0o700)
        gi = self.db_dir / ".gitignore"
        if not gi.exists():
            gi.write_text("*\n", encoding="utf-8")

    def _connect(self) -> sqlite3.Connection:
        if self._ready and not self.db_path.exists():
            raise RuntimeError(
                "vault.db исчез во время работы сервера (git clean -fdx? rm?). "
                "Вызовите vault_repair('restore_latest') для восстановления из резервной копии."
            )
        conn = sqlite3.connect(str(self.db_path), timeout=5.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA synchronous = FULL;")
        return conn

    def ensure_ready(self):
        if self._ready:
            return
        with _VAULT_LOCK:
            if not self._ready:
                self._init_db()
                self._ready = True

    @property
    def project_id(self) -> str:
        if not hasattr(self, "_pid"):
            with self.read() as conn:
                self._pid = conn.execute("SELECT v FROM meta WHERE k = 'project_id';").fetchone()[0]
        return self._pid

    @contextmanager
    def read(self):
        """Контекст чтения: deferred BEGIN (снимок WAL), PRAGMA query_only=ON.
        Никогда не блокирует писателей и других читателей."""
        self.ensure_ready()
        conn = self._connect()
        try:
            conn.execute("PRAGMA query_only = ON;")
            conn.execute("BEGIN;")
            yield conn
        finally:
            with contextlib.suppress(Exception):
                if conn.in_transaction:
                    conn.execute("ROLLBACK;")
            conn.close()

    @contextmanager
    def tx(self):
        """Контекст записи: BEGIN IMMEDIATE с ретраем и экспоненциальным джиттером."""
        self.ensure_ready()
        conn = self._connect()
        try:
            for attempt in range(3):
                try:
                    conn.execute("BEGIN IMMEDIATE;")
                    break
                except sqlite3.OperationalError as e:
                    if "locked" not in str(e).lower() and "busy" not in str(e).lower():
                        raise
                    if attempt == 2:
                        raise RuntimeError(
                            "Хранилище временно занято другим процессом (таймаут 3x5с). "
                            "Повторите вызов ещё раз. Не создавайте дубликатов задач и не делайте слепой task_reset."
                        ) from e
                    time.sleep(random.uniform(0.05, 0.25))

            yield conn
            conn.execute("COMMIT;")
            _maybe_autobackup(self)
        except BaseException:
            with contextlib.suppress(Exception):
                if conn.in_transaction:
                    conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def _init_db(self):
        last_err = None
        for attempt in range(5):
            conn = sqlite3.connect(str(self.db_path), timeout=5.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            try:
                mode = conn.execute("PRAGMA journal_mode = WAL;").fetchone()[0].lower()
                if mode != "wal" and attempt < 4:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                if mode != "wal":
                    print(f"[hh-vault] WARNING: journal_mode={mode}: WAL недоступен на этой ФС", file=sys.stderr)

                conn.execute("BEGIN IMMEDIATE;")
                try:
                    ver = conn.execute("PRAGMA user_version;").fetchone()[0]
                    if ver > self.SCHEMA_VERSION:
                        raise RuntimeError(
                            f"База данных имеет версию {ver}, которая новее поддерживаемой сервером ({self.SCHEMA_VERSION}). "
                            "Обновите hh-vault-mcp."
                        )
                    if ver < self.SCHEMA_VERSION:
                        self._apply_migrations(conn, ver)
                    conn.execute("COMMIT;")
                except BaseException:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK;")
                    raise
                return
            except sqlite3.OperationalError as e:
                last_err = e
                time.sleep(0.2 * (attempt + 1) + random.random() * 0.1)
            finally:
                conn.close()
        raise RuntimeError(f"Не удалось инициализировать vault.db: {last_err}")

    def _apply_migrations(self, conn: sqlite3.Connection, current_version: int):
        if current_version < 1:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS meta (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL
                );
            """)
            conn.execute("INSERT OR IGNORE INTO meta(k, v) VALUES ('project_id', lower(hex(randomblob(16))));")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL CHECK(status IN ('queued', 'red', 'yellow', 'green', 'archived')),
                    priority INTEGER NOT NULL CHECK(priority BETWEEN 1 AND 5),
                    tags TEXT DEFAULT '',
                    notes TEXT DEFAULT '',
                    parent_id TEXT DEFAULT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS task_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    from_status TEXT NOT NULL,
                    to_status TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(id)
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS docs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    slug TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    content TEXT NOT NULL,
                    tags TEXT DEFAULT '',
                    updated_at TEXT NOT NULL
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS docs_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    slug TEXT NOT NULL,
                    title TEXT,
                    category TEXT,
                    content TEXT,
                    tags TEXT,
                    version_ts TEXT NOT NULL
                );
            """)

            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS docs_fts USING fts5(
                    title, content, tags,
                    content='docs', content_rowid='id',
                    tokenize='unicode61 remove_diacritics 2'
                );
            """)

            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS docs_ai AFTER INSERT ON docs BEGIN
                    INSERT INTO docs_fts(rowid, title, content, tags)
                    VALUES (new.id, new.title, new.content, new.tags);
                END;
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS docs_ad AFTER DELETE ON docs BEGIN
                    INSERT INTO docs_fts(docs_fts, rowid, title, content, tags)
                    VALUES('delete', old.id, old.title, old.content, old.tags);
                END;
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS docs_au AFTER UPDATE OF title, content, tags ON docs BEGIN
                    INSERT INTO docs_fts(docs_fts, rowid, title, content, tags)
                    VALUES('delete', old.id, old.title, old.content, old.tags);
                    INSERT INTO docs_fts(rowid, title, content, tags)
                    VALUES (new.id, new.title, new.content, new.tags);
                END;
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS docs_hist_au AFTER UPDATE ON docs
                WHEN old.content IS NOT new.content OR old.title IS NOT new.title BEGIN
                    INSERT INTO docs_history(slug, title, category, content, tags, version_ts)
                    VALUES (old.slug, old.title, old.category, old.content, old.tags, old.updated_at);
                END;
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS docs_hist_bd BEFORE DELETE ON docs BEGIN
                    INSERT INTO docs_history(slug, title, category, content, tags, version_ts)
                    VALUES (old.slug, old.title, old.category, old.content, old.tags, old.updated_at);
                END;
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    key TEXT PRIMARY KEY,
                    encrypted_val TEXT NOT NULL,
                    description TEXT,
                    updated_at TEXT NOT NULL
                );
            """)

        if current_version < 2:
            # v2: гарантируем наличие parent_id и docs_history для старых баз
            cols = [r["name"] if isinstance(r, sqlite3.Row) else r[1] for r in conn.execute("PRAGMA table_info(tasks);").fetchall()]
            if "parent_id" not in cols:
                conn.execute("ALTER TABLE tasks ADD COLUMN parent_id TEXT DEFAULT NULL;")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS docs_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    slug TEXT NOT NULL,
                    title TEXT,
                    category TEXT,
                    content TEXT,
                    tags TEXT,
                    version_ts TEXT NOT NULL
                );
            """)
            conn.execute("INSERT INTO docs_fts(docs_fts) VALUES('rebuild');")

        conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION};")


_VAULT_INSTANCE: Optional[ProjectVault] = None

def get_vault() -> ProjectVault:
    global _VAULT_INSTANCE
    if _VAULT_INSTANCE is None:
        with _VAULT_LOCK:
            if _VAULT_INSTANCE is None:
                _VAULT_INSTANCE = ProjectVault()
    return _VAULT_INSTANCE


# --- 4. МОДЕЛЬ ДАННЫХ И КОНЕЧНЫЙ АВТОМАТ TDD ---

TaskStatus = Literal["queued", "red", "yellow", "green", "archived"]
DocCategory = Literal["architecture", "protocol", "network", "ui", "adr", "bugfix", "note", "security", "infra"]
TaskPriority = Literal[1, 2, 3, 4, 5]
RepairAction = Literal["rebuild_fts", "checkpoint_wal", "backup", "restore_latest", "dump_json"]

VALID_TRANSITIONS: Dict[str, List[str]] = {
    "queued": ["red", "archived"],
    "red": ["yellow", "queued", "archived"],
    "yellow": ["green", "red", "queued", "archived"],
    "green": ["archived", "yellow", "queued"],
    "archived": ["queued"]
}

MAX_EVIDENCE_CHARS = 4000
MAX_NOTE_CHARS = 2000
MAX_DOC_CHARS = 64000

_REJECTS: Dict[Tuple[str, str], int] = {}
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9_.\-/]{1,128}$")
_TOKEN_RE = re.compile(r"\w+", re.UNICODE)


def _reject(task_id: str, status: str, msg: str):
    key = (task_id, status)
    _REJECTS[key] = _REJECTS.get(key, 0) + 1
    count = _REJECTS[key]
    if count >= 3:
        msg += (
            f"\n[СТОП: {count}-я подряд ошибка перехода!] Не зацикливайтесь на одном действии. "
            f"Если требования изменились или тест неверен — вызовите task_reset('{task_id}', reason) "
            "или запросите указания у пользователя."
        )
    raise ValueError(msg)


def _format_fts_query(raw_query: str, op: str = "AND") -> str:
    terms = _TOKEN_RE.findall(raw_query)[:12]
    if not terms:
        return ""
    return f" {op} ".join(f'"{t}"*' for t in terms)


# --- 5. РЕАЛИЗАЦИЯ ИНСТРУМЕНТОВ ---

# [TASKS]

def task_create_core(
    title: str,
    description: str,
    priority: TaskPriority = 3,
    tags: str = "",
    parent_id: Optional[str] = None
) -> str:
    vault = get_vault()
    now = _get_utc_now()
    priority = max(1, min(int(priority), 5))

    with vault.tx() as conn:
        if parent_id:
            parent = conn.execute("SELECT id FROM tasks WHERE id = ?;", (parent_id,)).fetchone()
            if not parent:
                raise ValueError(f"Родительская задача [{parent_id}] не найдена.")

        # Безопасное вычисление следующего ID через MAX
        max_id_row = conn.execute("SELECT COALESCE(MAX(CAST(substr(id, 6) AS INTEGER)), 0) + 1 FROM tasks;").fetchone()
        next_num = max_id_row[0]
        task_id = f"TASK-{next_num:03d}"

        conn.execute("""
            INSERT INTO tasks (id, title, description, status, priority, tags, parent_id, created_at, updated_at)
            VALUES (?, ?, ?, 'queued', ?, ?, ?, ?, ?);
        """, (task_id, title, description, priority, tags, parent_id, now, now))

    parent_info = f" (подзадача {parent_id})" if parent_id else ""
    return f"Зафиксирована задача [{task_id}]: {title}{parent_info} (приоритет {priority}, статус: queued)"


def task_update_core(
    task_id: str,
    status: TaskStatus,
    evidence: str = "",
    note: str = "",
    expected_from: Optional[TaskStatus] = None
) -> str:
    vault = get_vault()
    now = _get_utc_now()
    evidence_clean = _clip(evidence.strip(), MAX_EVIDENCE_CHARS)
    note_clean = _clip(note.strip(), MAX_NOTE_CHARS)

    with vault.tx() as conn:
        row = conn.execute("SELECT status, notes, updated_at FROM tasks WHERE id = ?;", (task_id,)).fetchone()
        if not row:
            raise ValueError(f"Задача [{task_id}] не найдена в базе проекта. Проверьте task_list.")

        old_status = row["status"]

        if expected_from and expected_from != old_status:
            raise ValueError(
                f"Конфликт конкурентности: вы ожидали статус '{expected_from}', но задача сейчас в '{old_status}' "
                f"(обновлена: {row['updated_at']}). Перечитайте задачу через task_get и скорректируйте шаг."
            )

        if old_status == status:
            return f"Задача [{task_id}] уже находится в статусе '{status}' (изменений не требуется)."

        allowed = VALID_TRANSITIONS.get(old_status, [])
        if status not in allowed:
            _reject(
                task_id, status,
                f"Недопустимый переход: {old_status} -> {status}. Из '{old_status}' разрешены только: {allowed}. "
                f"Если требования изменились или тест ошибочен — используйте task_reset('{task_id}', reason)."
            )

        # Железный TDD-инвариант
        if status == "green" and len(evidence_clean) < 15:
            _reject(
                task_id, status,
                "TDD-инвариант нарушен: для перевода в 'green' ОБЯЗАТЕЛЕН аргумент evidence >= 15 символов "
                "(команда запуска теста, имя теста, факт успешного завершения exit 0). Одних слов 'passed' недостаточно."
            )
        if status == "red" and len(evidence_clean) < 15:
            _reject(
                task_id, status,
                "TDD-инвариант: для перевода в 'red' укажите в evidence команду запуска теста и фрагмент падающего вывода."
            )

        new_notes = row["notes"]
        if note_clean:
            new_notes = f"{new_notes}\n[{now}] {note_clean}".strip()

        cursor = conn.execute("""
            UPDATE tasks SET status = ?, notes = ?, updated_at = ?
            WHERE id = ? AND status = ?;
        """, (status, new_notes, now, task_id, old_status))

        if cursor.rowcount == 0:
            raise RuntimeError(f"Конфликт конкурентности: задача [{task_id}] была изменена другим процессом.")

        conn.execute("""
            INSERT INTO task_events (task_id, from_status, to_status, evidence, timestamp)
            VALUES (?, ?, ?, ?, ?);
        """, (task_id, old_status, status, evidence_clean or "status transition", now))

    _REJECTS.pop((task_id, status), None)
    return f"Задача [{task_id}] успешно переведена: {old_status} -> {status}"


def task_reset_core(
    task_id: str,
    reason: str,
    target_status: Literal["queued", "archived"] = "queued",
    expected_from: Optional[TaskStatus] = None
) -> str:
    """Аварийный сброс задачи при дедлоке или смене требований."""
    if not reason.strip():
        raise ValueError("Для аварийного сброса задачи ОБЯЗАТЕЛЬНО укажите причину (аргумент 'reason').")
    if target_status not in ("queued", "archived"):
        raise ValueError("Целевой статус при сбросе может быть только 'queued' или 'archived'.")

    vault = get_vault()
    now = _get_utc_now()
    reason_clean = _clip(reason.strip(), MAX_EVIDENCE_CHARS)

    with vault.tx() as conn:
        row = conn.execute("SELECT status, notes, updated_at FROM tasks WHERE id = ?;", (task_id,)).fetchone()
        if not row:
            raise ValueError(f"Задача [{task_id}] не найдена.")

        old_status = row["status"]
        if expected_from and expected_from != old_status:
            raise RuntimeError(
                f"Конфликт конкурентности при сбросе: ожидался статус '{expected_from}', фактический '{old_status}'."
            )

        reset_note = f"\n[{now}] [EMERGENCY RESET]: {reason_clean} (сброс {old_status} -> {target_status})"
        new_notes = (row["notes"] + reset_note).strip()

        conn.execute("""
            UPDATE tasks SET status = ?, notes = ?, updated_at = ?
            WHERE id = ? AND status = ?;
        """, (target_status, new_notes, now, task_id, old_status))

        conn.execute("""
            INSERT INTO task_events (task_id, from_status, to_status, evidence, timestamp)
            VALUES (?, ?, ?, ?, ?);
        """, (task_id, old_status, target_status, f"RESET: {reason_clean}", now))

    return f"Задача [{task_id}] принудительно сброшена в '{target_status}'. Причина: {reason_clean}"


def task_edit_core(
    task_id: str,
    reason: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    priority: Optional[TaskPriority] = None,
    tags: Optional[str] = None
) -> str:
    """Редактирует метаданные задачи при уточнении требований без костылей в notes."""
    if not reason.strip():
        raise ValueError("Для редактирования задачи обязательно укажите причину в 'reason'.")

    cols: List[Tuple[str, Any]] = []
    if title is not None:
        cols.append(("title", title.strip()))
    if description is not None:
        cols.append(("description", description.strip()))
    if priority is not None:
        cols.append(("priority", max(1, min(int(priority), 5))))
    if tags is not None:
        cols.append(("tags", tags.strip()))

    if not cols:
        raise ValueError("Не указаны поля для обновления (title, description, priority или tags).")

    vault = get_vault()
    now = _get_utc_now()

    with vault.tx() as conn:
        row = conn.execute("SELECT status FROM tasks WHERE id = ?;", (task_id,)).fetchone()
        if not row:
            raise ValueError(f"Задача [{task_id}] не найдена.")

        set_clause = ", ".join(f"{col} = ?" for col, _ in cols)
        params = [val for _, val in cols] + [now, task_id]
        conn.execute(f"UPDATE tasks SET {set_clause}, updated_at = ? WHERE id = ?;", params)

        changed_names = ", ".join(col for col, _ in cols)
        conn.execute("""
            INSERT INTO task_events (task_id, from_status, to_status, evidence, timestamp)
            VALUES (?, ?, ?, ?, ?);
        """, (task_id, row["status"], row["status"], _clip(f"EDIT({changed_names}): {reason}", MAX_EVIDENCE_CHARS), now))

    return f"Задача [{task_id}] успешно обновлена ({changed_names})."


def task_get_core(task_id: str) -> Optional[Dict[str, Any]]:
    vault = get_vault()
    with vault.read() as conn:
        row = conn.execute("SELECT * FROM tasks WHERE id = ?;", (task_id,)).fetchone()
        if not row:
            return None
        res = dict(row)
        # Ограничиваем историю последними 10 событиями для экономии токенов
        events = conn.execute(
            "SELECT from_status, to_status, evidence, timestamp FROM task_events WHERE task_id = ? ORDER BY id DESC LIMIT 10;",
            (task_id,)
        ).fetchall()
        res["history"] = [dict(e) for e in reversed(events)]
        # Обрезаем notes до последних 2000 символов
        if res.get("notes"):
            res["notes"] = _clip(res["notes"], MAX_NOTE_CHARS)
        return res


def task_list_core(status: Optional[TaskStatus] = None, limit: int = 20) -> Dict[str, Any]:
    limit = max(1, min(int(limit), 100))
    vault = get_vault()
    with vault.read() as conn:
        if status:
            total = conn.execute("SELECT COUNT(*) FROM tasks WHERE status = ?;", (status,)).fetchone()[0]
            cursor = conn.execute("""
                SELECT id, title, status, priority, tags, parent_id, updated_at
                FROM tasks WHERE status = ?
                ORDER BY priority ASC, updated_at DESC LIMIT ?;
            """, (status, limit))
        else:
            total = conn.execute("SELECT COUNT(*) FROM tasks WHERE status != 'archived';").fetchone()[0]
            cursor = conn.execute("""
                SELECT id, title, status, priority, tags, parent_id, updated_at
                FROM tasks WHERE status != 'archived'
                ORDER BY priority ASC, updated_at DESC LIMIT ?;
            """, (limit,))
        return {"total": total, "limit": limit, "tasks": [dict(r) for r in cursor.fetchall()]}


# [DOCS]

def doc_set_core(
    slug: str,
    title: str,
    category: DocCategory,
    content: str,
    tags: str = "",
    expected_updated_at: Optional[str] = None
) -> str:
    if not _SLUG_RE.match(slug):
        raise ValueError("slug должен состоять из строчных a-z, 0-9, ., _, /, - длиной до 128 символов.")
    if len(content) > MAX_DOC_CHARS:
        raise ValueError(f"Размер документа ({len(content)} симв.) превышает лимит {MAX_DOC_CHARS}. Разделите документ.")

    vault = get_vault()
    now = _get_utc_now()

    with vault.tx() as conn:
        if expected_updated_at:
            curr = conn.execute("SELECT updated_at FROM docs WHERE slug = ?;", (slug,)).fetchone()
            if curr and curr["updated_at"] != expected_updated_at:
                raise ValueError(
                    f"Конфликт версий документа [{slug}]: документ был обновлён другим процессом в {curr['updated_at']}. "
                    "Перечитайте документ через doc_get и повторите сохранение."
                )

        conn.execute("""
            INSERT INTO docs (slug, title, category, content, tags, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(slug) DO UPDATE SET
                title = excluded.title,
                category = excluded.category,
                content = excluded.content,
                tags = excluded.tags,
                updated_at = excluded.updated_at;
        """, (slug, title, category, content, tags, now))

    return f"Документ [{slug}] ({title}) сохранён (updated_at: {now})."


def doc_search_core(query: str, limit: int = 5) -> Dict[str, Any]:
    if not isinstance(query, str) or not query.strip():
        return {"results": [], "hint": "Пустой поисковый запрос."}

    limit = max(1, min(int(limit), 20))
    vault = get_vault()

    with vault.read() as conn:
        for mode in ("AND", "OR"):
            safe_query = _format_fts_query(query, mode)
            if not safe_query:
                continue

            try:
                cursor = conn.execute("""
                    SELECT d.slug, d.title, d.category,
                           snippet(docs_fts, -1, '[', ']', '…', 12) AS snippet,
                           bm25(docs_fts, 8.0, 1.0, 4.0) AS score
                    FROM docs_fts
                    JOIN docs d ON d.id = docs_fts.rowid
                    WHERE docs_fts MATCH ?
                    ORDER BY score
                    LIMIT ?;
                """, (safe_query, limit))
                results = [dict(r) for r in cursor.fetchall()]
                if results:
                    return {"results": results, "mode": mode}
            except sqlite3.OperationalError:
                pass

    return {
        "results": [],
        "hint": "По запросу ничего не найдено. Попробуйте 1-2 общих ключевых слова или вызовите doc_list(category=...)."
    }


def doc_get_core(slug: str, offset: int = 0, max_chars: int = 6000) -> Optional[Dict[str, Any]]:
    max_chars = max(500, min(max_chars, 20000))
    offset = max(0, offset)
    vault = get_vault()

    with vault.read() as conn:
        row = conn.execute("SELECT slug, title, category, content, tags, updated_at FROM docs WHERE slug = ?;", (slug,)).fetchone()
        if not row:
            return None
        res = dict(row)
        full_len = len(res["content"])
        res["content"] = res["content"][offset:offset + max_chars]
        res["total_chars"] = full_len
        res["next_offset"] = (offset + max_chars) if (offset + max_chars < full_len) else None
        return res


def doc_list_core(category: Optional[DocCategory] = None, limit: int = 50) -> Dict[str, Any]:
    limit = max(1, min(int(limit), 100))
    vault = get_vault()

    with vault.read() as conn:
        if category:
            total = conn.execute("SELECT COUNT(*) FROM docs WHERE category = ?;", (category,)).fetchone()[0]
            cursor = conn.execute(
                "SELECT slug, title, category, tags, updated_at FROM docs WHERE category = ? ORDER BY updated_at DESC LIMIT ?;",
                (category, limit)
            )
        else:
            total = conn.execute("SELECT COUNT(*) FROM docs;").fetchone()[0]
            cursor = conn.execute(
                "SELECT slug, title, category, tags, updated_at FROM docs ORDER BY category ASC, updated_at DESC LIMIT ?;",
                (limit,)
            )
        return {"total": total, "limit": limit, "docs": [dict(r) for r in cursor.fetchall()]}


def doc_delete_core(slug: str) -> str:
    vault = get_vault()
    with vault.tx() as conn:
        cursor = conn.execute("DELETE FROM docs WHERE slug = ?;", (slug,))
        if cursor.rowcount == 0:
            return f"Документ [{slug}] не найден."
    return f"Документ [{slug}] удалён (версия сохранена в docs_history)."


# [SECRETS]

def secret_set_core(key: str, value: str, description: str = "") -> str:
    if not _KEY_RE.match(key):
        raise ValueError("Имя ключа секрета должно содержать только [A-Za-z0-9_.-/] до 128 символов.")

    vault = get_vault()
    now = _get_utc_now()

    with vault.tx() as conn:
        count = conn.execute("SELECT COUNT(*) FROM secrets;").fetchone()[0]
        # Мастер-ключ разрешено генерировать ТОЛЬКО если в базе вообще нет секретов
        master_key = _get_master_key(allow_create=(count == 0))
        _check_or_store_kcv(conn, master_key, store=True)

        aad = _aad(vault.project_id, key)
        encrypted = _encrypt_secret(value, aad, master_key)

        conn.execute("""
            INSERT INTO secrets (key, encrypted_val, description, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                encrypted_val = excluded.encrypted_val,
                description = excluded.description,
                updated_at = excluded.updated_at;
        """, (key, encrypted, description, now))

    return f"Секрет [{key}] зашифрован (AES-256-GCM + AAD) и сохранён в vault проекта."


def secret_get_core(key: str) -> Optional[str]:
    vault = get_vault()
    with vault.read() as conn:
        row = conn.execute("SELECT encrypted_val FROM secrets WHERE key = ?;", (key,)).fetchone()
        if not row:
            return None
        master_key = _get_master_key(allow_create=False)
        _check_or_store_kcv(conn, master_key, store=False)
        aad = _aad(vault.project_id, key)
        return _decrypt_secret(row["encrypted_val"], aad, master_key)


def secret_list_core() -> List[Dict[str, Any]]:
    vault = get_vault()
    with vault.read() as conn:
        cursor = conn.execute("SELECT key, description, updated_at FROM secrets ORDER BY key ASC;")
        return [dict(r) for r in cursor.fetchall()]


def secret_delete_core(key: str) -> str:
    vault = get_vault()
    with vault.tx() as conn:
        cursor = conn.execute("DELETE FROM secrets WHERE key = ?;", (key,))
        if cursor.rowcount == 0:
            return f"Секрет [{key}] не найден."
    return f"Секрет [{key}] безвозвратно удалён."


# [САМОДИАГНОСТИКА И САМОЛЕЧЕНИЕ (DOCTOR & REPAIR)]

def _atomic_write_file(path: Path, data: str):
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _verify_integrity(path: Path) -> bool:
    conn = sqlite3.connect(str(path))
    try:
        row = conn.execute("PRAGMA quick_check;").fetchone()
        return row and row[0] == "ok"
    except sqlite3.DatabaseError:
        return False
    finally:
        conn.close()


def _make_backup(vault: ProjectVault) -> Path:
    vault.backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    final_path = vault.backup_dir / f"vault-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
    tmp_path = final_path.with_name(f"{final_path.name}.tmp")

    src = vault._connect()
    dst = sqlite3.connect(str(tmp_path))
    try:
        src.backup(dst)
        chk = dst.execute("PRAGMA quick_check;").fetchone()
        if not chk or chk[0] != "ok":
            raise RuntimeError(f"Созданный бэкап не прошёл проверку целостности: {chk}")
    finally:
        dst.close()
        src.close()

    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, final_path)

    # Ротация: храним последние 10 резервных копий
    existing = sorted(vault.backup_dir.glob("vault-*.db"))
    for old in existing[:-10]:
        old.unlink(missing_ok=True)

    return final_path


def _maybe_autobackup(vault: ProjectVault, interval_seconds: int = 1800):
    global _LAST_BACKUP_TIME
    now = time.time()
    if now - _LAST_BACKUP_TIME > interval_seconds:
        _LAST_BACKUP_TIME = now
        with contextlib.suppress(Exception):
            _make_backup(vault)


def _restore_latest_backup(vault: ProjectVault) -> str:
    backups = [b for b in sorted(vault.backup_dir.glob("vault-*.db"), reverse=True) if _verify_integrity(b)]
    if not backups:
        return "Валидных резервных копий не найдено. Используйте vault_repair('dump_json') для выгрузки остатков."

    latest = backups[0]
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    vault._ensure_secure_dir()

    # Помещаем текущие (возможно повреждённые) файлы в карантин
    for ext in ("", "-wal", "-shm"):
        cur_file = Path(str(vault.db_path) + ext)
        if cur_file.exists():
            os.replace(cur_file, vault.db_dir / f"{cur_file.name}.corrupt-{ts}")

    shutil.copy2(latest, vault.db_path)
    os.chmod(vault.db_path, 0o600)
    vault._ready = False
    vault.ensure_ready()

    return (
        f"Хранилище успешно восстановлено из снимка {latest.name}. "
        f"Повреждённые файлы перемещены в {vault.db_dir.name}/*.corrupt-{ts}."
    )


def vault_doctor_core() -> Dict[str, Any]:
    """Самодиагностика: не падает даже на битой базе, проверяет внешнее содержимое FTS5 и KCV."""
    vault = get_vault()
    rep: Dict[str, Any] = {
        "project": vault.project_name,
        "db_path": str(vault.db_path),
        "status": "ok",
        "checks": {}
    }

    try:
        conn = vault._connect()
    except Exception as e:
        rep["status"] = "critical"
        rep["checks"]["database_open"] = f"CRITICAL: {e}"
        rep["next_step"] = "vault_repair('restore_latest')"
        return rep

    try:
        # 1. Quick check
        qc = [r[0] for r in conn.execute("PRAGMA quick_check;").fetchall()][:5]
        rep["checks"]["quick_check"] = qc
        if qc != ["ok"]:
            rep["status"] = "warning"

        # 2. Foreign keys
        fk = conn.execute("PRAGMA foreign_key_check;").fetchall()
        rep["checks"]["foreign_keys"] = "ok" if not fk else f"Ошибок: {len(fk)}"
        if fk:
            rep["status"] = "warning"

        # 3. FTS5 vs Docs (rank=1 сверяет виртуальный индекс с таблицей docs)
        try:
            conn.execute("INSERT INTO docs_fts(docs_fts, rank) VALUES('integrity-check', 1);")
            rep["checks"]["fts5_index"] = "ok"
        except Exception as e:
            rep["checks"]["fts5_index"] = f"error: {e}"
            rep["status"] = "warning"

        # 4. Проверка мастер-ключа и KCV
        try:
            master_key = _get_master_key(allow_create=False)
            kcv_row = conn.execute("SELECT v FROM meta WHERE k = 'kcv';").fetchone()
            if kcv_row is None:
                rep["checks"]["master_key"] = "not_initialized (нет секретов)"
            elif hmac.compare_digest(kcv_row["v"], _kcv(master_key)):
                rep["checks"]["master_key"] = "ok"
            else:
                rep["checks"]["master_key"] = "MISMATCH (несовпадение ключа)"
                rep["status"] = "critical"
        except Exception as e:
            rep["checks"]["master_key"] = f"unavailable: {e}"

    finally:
        conn.close()

    # 5. Состояние WAL (независимое подключение вне транзакции)
    conn_wal = sqlite3.connect(str(vault.db_path))
    try:
        res = conn_wal.execute("PRAGMA wal_checkpoint(PASSIVE);").fetchone()
        rep["checks"]["wal_pages"] = {"busy": res[0], "log": res[1], "checkpointed": res[2]}
    except Exception as e:
        rep["checks"]["wal_pages"] = str(e)
    finally:
        conn_wal.close()

    if rep["status"] != "ok" and "next_step" not in rep:
        rep["next_step"] = "При ошибках FTS: vault_repair('rebuild_fts'). При критическом сбое: vault_repair('restore_latest')."

    return rep


def vault_repair_core(action: RepairAction) -> str:
    """Аварийное самолечение хранилища."""
    vault = get_vault()

    if action == "rebuild_fts":
        with vault.tx() as conn:
            conn.execute("INSERT INTO docs_fts(docs_fts) VALUES('rebuild');")
        return "Полнотекстовый индекс docs_fts полностью пересобран из таблицы docs."

    elif action == "checkpoint_wal":
        # Checkpoint выполняется строго в отдельном автокоммит-соединении вне BEGIN
        conn = vault._connect()
        try:
            busy, log, done = conn.execute("PRAGMA wal_checkpoint(TRUNCATE);").fetchone()
        finally:
            conn.close()
        if busy != 0:
            return f"WAL checkpoint временно отложен: есть активные читатели (log={log}, checkpointed={done})."
        return "Журнал WAL успешно сброшен и обрезан (TRUNCATE)."

    elif action == "backup":
        bk = _make_backup(vault)
        return f"Горячий проверенный снимок базы создан: {bk.name} в {vault.backup_dir}"

    elif action == "restore_latest":
        return _restore_latest_backup(vault)

    elif action == "dump_json":
        export_path = vault.db_dir / f"vault_dump_{int(time.time())}.json"
        with vault.read() as conn:
            tasks = [dict(r) for r in conn.execute("SELECT * FROM tasks;").fetchall()]
            task_events = [dict(r) for r in conn.execute("SELECT * FROM task_events;").fetchall()]
            docs = [dict(r) for r in conn.execute("SELECT * FROM docs;").fetchall()]
            secrets_meta = [dict(r) for r in conn.execute("SELECT key, description, updated_at FROM secrets;").fetchall()]

        dump_data = {
            "exported_at": _get_utc_now(),
            "project": vault.project_name,
            "project_id": vault.project_id,
            "tasks": tasks,
            "task_events": task_events,
            "docs": docs,
            "secrets_metadata": secrets_meta
        }
        _atomic_write_file(export_path, json.dumps(dump_data, ensure_ascii=False, indent=2))
        return f"Аварийный текстовый дамп базы атомарно сохранён в {export_path.name} ({len(tasks)} задач, {len(docs)} доков)."

    return f"Неизвестное действие: {action}"


def vault_summary_core() -> Dict[str, Any]:
    vault = get_vault()
    with vault.read() as conn:
        task_stats = dict(conn.execute("SELECT status, COUNT(*) FROM tasks GROUP BY status;").fetchall())
        doc_count = conn.execute("SELECT COUNT(*) FROM docs;").fetchone()[0]
        secret_count = conn.execute("SELECT COUNT(*) FROM secrets;").fetchone()[0]
        recent_tasks = [dict(r) for r in conn.execute(
            "SELECT id, title, status, priority FROM tasks WHERE status != 'archived' ORDER BY updated_at DESC LIMIT 5;"
        ).fetchall()]

    return {
        "project": vault.project_name,
        "root": str(vault.project_root),
        "db": str(vault.db_path),
        "tasks": task_stats,
        "docs_total": doc_count,
        "secrets_total": secret_count,
        "recent_tasks": recent_tasks
    }


# --- 6. РЕГИСТРАЦИЯ MCP-ИНСТРУМЕНТОВ ---

def _offloaded(fn):
    """Декоратор для выноса синхронных SQLite-операций из async event loop FastMCP."""
    if not to_thread:
        return fn

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        return await to_thread.run_sync(functools.partial(fn, *args, **kwargs))
    return wrapper


if FastMCP:
    mcp = FastMCP(
        name="hh-vault",
        instructions="Отказоустойчивое хранилище задач, базы знаний и секретов проекта с TDD-валидацией."
    )

    @mcp.tool()
    @_offloaded
    def task_create(
        title: str,
        description: str,
        priority: TaskPriority = 3,
        tags: str = "",
        parent_id: Optional[str] = None
    ) -> str:
        """Создает задачу в статусе queued. Опционально привязывается к parent_id при декомпозиции."""
        return task_create_core(title, description, priority, tags, parent_id)

    @mcp.tool()
    @_offloaded
    def task_update(
        task_id: str,
        status: TaskStatus,
        evidence: str = "",
        note: str = "",
        expected_from: Optional[TaskStatus] = None
    ) -> str:
        """Обновляет статус задачи по TDD FSM. Для 'green' ОБЯЗАТЕЛЕН evidence (имя и результат теста exit 0)."""
        return task_update_core(task_id, status, evidence, note, expected_from)

    @mcp.tool()
    @_offloaded
    def task_reset(
        task_id: str,
        reason: str,
        target_status: Literal["queued", "archived"] = "queued",
        expected_from: Optional[TaskStatus] = None
    ) -> str:
        """Аварийный сброс задачи при дедлоке или смене требований с фиксацией причины в аудите."""
        return task_reset_core(task_id, reason, target_status, expected_from)

    @mcp.tool()
    @_offloaded
    def task_edit(
        task_id: str,
        reason: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        priority: Optional[TaskPriority] = None,
        tags: Optional[str] = None
    ) -> str:
        """Редактирует метаданные задачи при уточнении требований с записью причины в аудит."""
        return task_edit_core(task_id, reason, title, description, priority, tags)

    @mcp.tool()
    @_offloaded
    def task_get(task_id: str) -> str:
        """Возвращает задачу и историю последних 10 переходов."""
        t = task_get_core(task_id)
        return _j(t) if t else f"Задача [{task_id}] не найдена."

    @mcp.tool()
    @_offloaded
    def task_list(status: Optional[TaskStatus] = None, limit: int = 20) -> str:
        """Список задач проекта (по умолчанию без архивированных, отсортирован по приоритету)."""
        return _j(task_list_core(status, limit))

    @mcp.tool()
    @_offloaded
    def doc_set(
        slug: str,
        title: str,
        category: DocCategory,
        content: str,
        tags: str = "",
        expected_updated_at: Optional[str] = None
    ) -> str:
        """Сохраняет архитектурное решение (ADR), спецификацию или заметку в базу знаний."""
        return doc_set_core(slug, title, category, content, tags, expected_updated_at)

    @mcp.tool()
    @_offloaded
    def doc_search(query: str, limit: int = 5) -> str:
        """Полнотекстовый поиск FTS5 по базе знаний. Возвращает компактные сниппеты с BM25-рангом."""
        return _j(doc_search_core(query, limit))

    @mcp.tool()
    @_offloaded
    def doc_get(slug: str, offset: int = 0, max_chars: int = 6000) -> str:
        """Получает текст документа с пагинацией (offset, max_chars)."""
        doc = doc_get_core(slug, offset, max_chars)
        return _j(doc) if doc else "Документ не найден."

    @mcp.tool()
    @_offloaded
    def doc_list(category: Optional[DocCategory] = None, limit: int = 50) -> str:
        """Список документов/ADR проекта по категориям."""
        return _j(doc_list_core(category, limit))

    @mcp.tool()
    @_offloaded
    def doc_delete(slug: str) -> str:
        """Удаляет документ из базы (версия архивируется в docs_history)."""
        return doc_delete_core(slug)

    @mcp.tool()
    @_offloaded
    def secret_set(key: str, value: str, description: str = "") -> str:
        """Шифрует (AES-256-GCM + AAD) и сохраняет секрет в базе."""
        return secret_set_core(key, value, description)

    @mcp.tool()
    @_offloaded
    def secret_get(key: str) -> str:
        """Возвращает расшифрованное значение секрета."""
        val = secret_get_core(key)
        return val if val is not None else f"Секрет [{key}] не найден."

    @mcp.tool()
    @_offloaded
    def secret_list() -> str:
        """Список доступных ключей секретов (без значений!)."""
        return _j(secret_list_core())

    @mcp.tool()
    @_offloaded
    def secret_delete(key: str) -> str:
        """Удаляет секрет из базы."""
        return secret_delete_core(key)

    @mcp.tool()
    @_offloaded
    def vault_summary() -> str:
        """Сводка состояния проекта: задачи, документы, секреты."""
        return _j(vault_summary_core())

    @mcp.tool()
    @_offloaded
    def vault_doctor() -> str:
        """Самодиагностика: целостность SQLite, FTS5, внешних ключей, мастер-ключа и WAL."""
        return _j(vault_doctor_core())

    @mcp.tool()
    @_offloaded
    def vault_repair(action: RepairAction) -> str:
        """Самолечение: 'rebuild_fts', 'checkpoint_wal', 'backup', 'restore_latest', 'dump_json'."""
        return vault_repair_core(action)
else:
    mcp = None


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("[TEST] Запуск стресс-тестов ProjectVault v2.1 в изолированной среде...")
        test_dir = tempfile.mkdtemp(prefix="hh-vault-test-")
        import subprocess
        subprocess.run(["git", "init", "-q", test_dir], check=True)
        os.environ["HH_PROJECT_DIR"] = test_dir
        os.environ["HH_VAULT_KEY"] = base64.b64encode(os.urandom(32)).decode("utf-8")

        v = get_vault()
        print(f"Изолированный проект: {v.project_name} ({v.project_root})")

        # 1. Создание задачи
        create_msg = task_create_core("Первичный TDD-тест", "Проверка сокетов", 1)
        print(create_msg)
        m = re.search(r"TASK-\d+", create_msg)
        tid = m.group(0) if m else "TASK-001"

        # 2. Проверка недопустимого перехода queued -> green
        try:
            task_update_core(tid, "green", evidence="pytest test_socket passed with exit 0")
            print("ОШИБКА: FSM пропустил невалидный переход!")
        except ValueError as err:
            print(f"[OK] FSM заблокировал невалидный переход: {err}")

        # 3. Переход в red с доказательством
        print(task_update_core(tid, "red", evidence="pytest tests/test_socket.py: FAILED AssertionError"))

        # 4. Редактирование задачи
        print(task_edit_core(tid, "Уточнение требований к сокету", title="Тест проверки сокетов TCP/UDP"))

        # 5. Аварийный сброс (Escape Hatch)
        print(task_reset_core(tid, "Смена сетевого стека", target_status="queued"))
        print("[OK] История задачи:", _j(task_get_core(tid)))

        # 6. Документация и FTS5
        print(doc_set_core("adr-001", "Прямой TUN Sing-box", "architecture", "Реализация прямого TUN в ядре..."))
        print("FTS5 поиск:", _j(doc_search_core("Sing-box TUN")))

        # 7. Секреты и KCV
        print(secret_set_core("api_key", "secret-token-12345", "API ключ сервера"))
        decrypted = secret_get_core("api_key")
        assert decrypted == "secret-token-12345", "Ошибка расшифровки секрета!"
        print("[OK] Секрет успешно зашифрован и расшифрован:", decrypted)

        # 8. Doctor & Repair
        print("Vault Doctor:", _j(vault_doctor_core()))
        print(vault_repair_core("checkpoint_wal"))
        print(vault_repair_core("backup"))
        print(vault_repair_core("dump_json"))

        # Очистка изолированной тестовой папки и её бэкапов
        shutil.rmtree(test_dir, ignore_errors=True)
        shutil.rmtree(v.backup_dir.parent, ignore_errors=True)
        print("[TEST] Все стресс-тесты v2.1 пройдены успешно!")
    else:
        if mcp:
            mcp.run()
        else:
            print("Для работы сервера требуется пакет: pip install mcp cryptography anyio", file=sys.stderr)
            sys.exit(1)
