"""Host-local attachment I/O shared by MCP and AX; never read AMX's private state."""

from __future__ import annotations

import os
import stat
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path

from amx.attachments import (
    EXECUTABLE_TYPES,
    Attachment,
    ReceivedAttachment,
    safe_filename,
    sniff_type,
)

_SAFE_DIR_FD = (
    all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
    and {os.open, os.mkdir, os.stat, os.link, os.unlink} <= os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
)


@contextmanager
def _directory(path: Path, *, create: bool = False) -> Iterator[tuple[int, Callable[[], None]]]:
    """Open a canonical absolute path one no-follow component at a time.

    Keep all ancestor FDs alive and verify their entries still name the opened
    directories before I/O. Every subsequent operation is FD-relative, so even a
    swap after validation cannot redirect it. No /proc or platform-specific FD
    pathname lookup is needed (Linux and macOS support these POSIX operations).
    """
    if not _SAFE_DIR_FD:
        raise ValueError("safe descriptor-relative attachment I/O is unavailable")
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("attachment directory must be canonical and absolute")
    chain: list[tuple[int, str, int]] = []

    def validate() -> None:
        for parent, name, child in chain:
            entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
            opened = os.fstat(child)
            if not stat.S_ISDIR(entry.st_mode) or (entry.st_dev, entry.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                raise ValueError("attachment directory changed during traversal")

    with ExitStack() as stack:
        folder = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, folder)
        for component in path.parts[1:]:
            if create:
                with suppress(FileExistsError):
                    os.mkdir(component, 0o700, dir_fd=folder)
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=folder)
            stack.callback(os.close, child)
            chain.append((folder, component, child))
            folder = child
            validate()
        yield folder, validate


def private_directories(extra: Sequence[Path] = ()) -> tuple[Path, ...]:
    """Default state/config/credentials, plus explicit runner or custody locations."""
    home = Path.home()
    roots = [
        Path(os.environ.get(variable, home / default)) / "amx"
        for variable, default in (
            ("XDG_DATA_HOME", ".local/share"),
            ("XDG_STATE_HOME", ".local/state"),
            ("XDG_CONFIG_HOME", ".config"),
        )
    ]
    roots += [home / ".amx", Path("runner-state"), *extra]
    return tuple(root.expanduser().resolve() for root in roots)


def load_files(
    paths: Sequence[str] | None, *, max_bytes: int, forbidden: Sequence[Path] = ()
) -> tuple[Attachment, ...]:
    """Resolve, confine and stat each regular file before any bounded read."""
    if paths is None:
        return ()
    if isinstance(paths, (str, bytes)) or any(not isinstance(path, str) for path in paths):
        raise ValueError("attachments must be a list of file paths")
    denied = private_directories(forbidden)
    result = []
    total = 0
    for value in paths:
        try:
            path = Path(value).expanduser().resolve(strict=True)
            if any(path.is_relative_to(root) for root in denied):
                raise ValueError("attachment path is inside AMX state or credential directories")
            with _directory(path.parent) as (folder, validate):
                # NONBLOCK also prevents a raced FIFO from hanging a tool.
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
                with os.fdopen(fd, "rb") as stream:
                    validate()
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode):
                        raise ValueError("attachment path must be a readable regular file")
                    if info.st_nlink > 1:
                        raise ValueError("attachment hard links are refused")
                    if info.st_size + total > max_bytes:
                        raise ValueError(f"attachment files exceed limits.max_bytes={max_bytes}")
                    content = stream.read(max_bytes - total + 1)
            total += len(content)
            if total > max_bytes:
                raise ValueError(f"attachment files exceed limits.max_bytes={max_bytes}")
        except OSError:
            raise ValueError("attachment path must resolve to a readable regular file") from None
        name = safe_filename(path.name)
        if sniff_type(content, name) in EXECUTABLE_TYPES:
            raise ValueError("executable attachments are refused")
        result.append(Attachment(name, content))
    return tuple(result)


def file_metadata(files: Sequence[Attachment]) -> list[dict[str, str | int]]:
    return [
        {
            "filename": item.filename,
            "type": sniff_type(item.content, item.filename),
            "size": len(item.content),
        }
        for item in files
    ]


def agent_state(address: str) -> Path:
    from amx.host import default_state_home, service_id

    return default_state_home() / service_id(address)


def attachment_directory(state: Path, task: str | None) -> Path:
    return state / "attachments" / safe_filename(task or "unthreaded")


def save_file(attachment: ReceivedAttachment, directory: Path) -> Path:
    """Stage owner-only bytes, then atomically publish without overwriting any entry."""
    content = attachment.content
    directory = directory.expanduser().resolve()
    name = safe_filename(attachment.filename)
    with _directory(directory, create=True) as (folder, validate):
        temporary = f".amx-{uuid.uuid4().hex}.tmp"
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=folder
        )
        published: str | None = None
        try:
            with os.fdopen(fd, "wb") as stream:
                validate()
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            suffix = 0
            while True:
                candidate = name if not suffix else f"{suffix}-{name}"
                validate()
                try:
                    # link is atomic and fails if the destination exists, including a symlink.
                    os.link(
                        temporary,
                        candidate,
                        src_dir_fd=folder,
                        dst_dir_fd=folder,
                        follow_symlinks=False,
                    )
                    published = candidate
                    validate()
                    os.fsync(folder)
                    return directory / candidate
                except FileExistsError:
                    suffix += 1
        except BaseException:
            if published is not None:
                os.unlink(published, dir_fd=folder)
            raise
        finally:
            os.unlink(temporary, dir_fd=folder)


def remove_saved_file(path: Path) -> None:
    """Remove an exclusively created offer file without following replaced ancestors."""
    with _directory(path.parent) as (folder, validate):
        validate()
        os.unlink(path.name, dir_fd=folder)
