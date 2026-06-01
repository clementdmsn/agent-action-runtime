import pytest

from agent_action_runtime.context import RuntimeContext, RuntimeLimits
from agent_action_runtime.errors import SandboxError
from agent_action_runtime.sandbox import (
    list_directory,
    read_text_file,
    resolve_workspace_path,
    write_text_file,
)


def test_resolve_workspace_path_allows_inside_path(tmp_path) -> None:
    context = RuntimeContext(workspace_root=tmp_path)

    resolved = resolve_workspace_path("notes.txt", context)

    assert resolved == tmp_path / "notes.txt"


def test_resolve_workspace_path_blocks_escape(tmp_path) -> None:
    context = RuntimeContext(workspace_root=tmp_path)

    with pytest.raises(SandboxError) as error:
        resolve_workspace_path("../outside.txt", context)

    assert error.value.code == "filesystem.workspace_escape"


def test_read_write_and_list_directory(tmp_path) -> None:
    context = RuntimeContext(workspace_root=tmp_path)

    write_text_file("nested/notes.txt", "hello", context)

    assert read_text_file("nested/notes.txt", context) == "hello"
    assert list_directory("nested", context) == ["notes.txt"]


def test_write_size_limit_is_enforced(tmp_path) -> None:
    context = RuntimeContext(
        workspace_root=tmp_path,
        limits=RuntimeLimits(max_write_chars=3),
    )

    with pytest.raises(SandboxError) as error:
        write_text_file("large.txt", "toolong", context)

    assert error.value.code == "filesystem.write_too_large"
