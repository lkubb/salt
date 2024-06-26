import pytest

import salt.states.win_wusa as wusa
from salt.exceptions import SaltInvocationError
from tests.support.mock import MagicMock, patch


@pytest.fixture
def kb():
    return "KB123456"


@pytest.fixture
def configure_loader_modules():
    return {wusa: {"__opts__": {"test": False}, "__env__": "base"}}


def test_installed_no_source():
    """
    test wusa.installed without passing source
    """
    with pytest.raises(SaltInvocationError) as excinfo:
        wusa.installed(name="KB123456", source=None)
        assert excinfo.exception.strerror == 'Must specify a "source" file to install'


def test_installed_existing(kb):
    """
    test wusa.installed when the kb is already installed
    """
    mock_installed = MagicMock(return_value=True)
    with patch.dict(wusa.__salt__, {"wusa.is_installed": mock_installed}):
        returned = wusa.installed(name=kb, source=f"salt://{kb}.msu")
        expected = {
            "changes": {},
            "comment": f"{kb} already installed",
            "name": kb,
            "result": True,
        }
        assert expected == returned


def test_installed_test_true(kb):
    """
    test wusa.installed with test=True
    """
    mock_installed = MagicMock(return_value=False)
    with patch.dict(wusa.__salt__, {"wusa.is_installed": mock_installed}), patch.dict(
        wusa.__opts__, {"test": True}
    ):
        returned = wusa.installed(name=kb, source=f"salt://{kb}.msu")
        expected = {
            "changes": {},
            "comment": f"{kb} would be installed",
            "name": kb,
            "result": None,
        }
        assert expected == returned


def test_installed_cache_fail(kb):
    """
    test wusa.install when it fails to cache the file
    """
    mock_installed = MagicMock(return_value=False)
    mock_cache = MagicMock(return_value="")
    with patch.dict(
        wusa.__salt__,
        {"wusa.is_installed": mock_installed, "cp.cache_file": mock_cache},
    ):
        returned = wusa.installed(name=kb, source=f"salt://{kb}.msu")
        expected = {
            "changes": {},
            "comment": f'Unable to cache salt://{kb}.msu from saltenv "base"',
            "name": kb,
            "result": False,
        }
        assert expected == returned


def test_installed(kb):
    """
    test wusa.installed assuming success
    """
    mock_installed = MagicMock(side_effect=[False, True])
    mock_cache = MagicMock(return_value=f"C:\\{kb}.msu")
    with patch.dict(
        wusa.__salt__,
        {
            "wusa.is_installed": mock_installed,
            "cp.cache_file": mock_cache,
            "wusa.install": MagicMock(),
        },
    ):
        returned = wusa.installed(name=kb, source=f"salt://{kb}.msu")
        expected = {
            "changes": {"new": True, "old": False},
            "comment": f"{kb} was installed. ",
            "name": kb,
            "result": True,
        }
        assert expected == returned


def test_installed_failed(kb):
    """
    test wusa.installed with a failure
    """
    mock_installed = MagicMock(side_effect=[False, False])
    mock_cache = MagicMock(return_value=f"C:\\{kb}.msu")
    with patch.dict(
        wusa.__salt__,
        {
            "wusa.is_installed": mock_installed,
            "cp.cache_file": mock_cache,
            "wusa.install": MagicMock(),
        },
    ):
        returned = wusa.installed(name=kb, source=f"salt://{kb}.msu")
        expected = {
            "changes": {},
            "comment": f"{kb} failed to install. ",
            "name": kb,
            "result": False,
        }
        assert expected == returned


def test_uninstalled_non_existing(kb):
    """
    test wusa.uninstalled when the kb is not installed
    """
    mock_installed = MagicMock(return_value=False)
    with patch.dict(wusa.__salt__, {"wusa.is_installed": mock_installed}):
        returned = wusa.uninstalled(name=kb)
        expected = {
            "changes": {},
            "comment": f"{kb} already uninstalled",
            "name": kb,
            "result": True,
        }
        assert expected == returned


def test_uninstalled_test_true(kb):
    """
    test wusa.uninstalled with test=True
    """
    mock_installed = MagicMock(return_value=True)
    with patch.dict(wusa.__salt__, {"wusa.is_installed": mock_installed}), patch.dict(
        wusa.__opts__, {"test": True}
    ):
        returned = wusa.uninstalled(name=kb)
        expected = {
            "changes": {},
            "comment": f"{kb} would be uninstalled",
            "name": kb,
            "result": None,
        }
        assert expected == returned


def test_uninstalled(kb):
    """
    test wusa.uninstalled assuming success
    """
    mock_installed = MagicMock(side_effect=[True, False])
    with patch.dict(
        wusa.__salt__,
        {"wusa.is_installed": mock_installed, "wusa.uninstall": MagicMock()},
    ):
        returned = wusa.uninstalled(name=kb)
        expected = {
            "changes": {"new": False, "old": True},
            "comment": f"{kb} was uninstalled",
            "name": kb,
            "result": True,
        }
        assert expected == returned


def test_uninstalled_failed(kb):
    """
    test wusa.uninstalled with a failure
    """
    mock_installed = MagicMock(side_effect=[True, True])
    with patch.dict(
        wusa.__salt__,
        {"wusa.is_installed": mock_installed, "wusa.uninstall": MagicMock()},
    ):
        returned = wusa.uninstalled(name=kb)
        expected = {
            "changes": {},
            "comment": f"{kb} failed to uninstall",
            "name": kb,
            "result": False,
        }
        assert expected == returned
