import pytest

import blackbox
from blackbox.cli import main


def test_version_is_set():
    assert blackbox.__version__


def test_cli_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert blackbox.__version__ in capsys.readouterr().out
