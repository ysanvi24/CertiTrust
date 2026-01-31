import pytest
import os
from pathlib import Path

@pytest.fixture
def temp_file(tmp_path):
    d = tmp_path / "subdir"
    d.mkdir()
    p = d / "test_file.txt"
    p.write_text("Hello World!")
    return p
