import shutil
import subprocess
from pathlib import Path

import psutil
import pytest

try:
    import gnupg as gnupglib

    HAS_GNUPG = True
except ImportError:
    HAS_GNUPG = False


pytestmark = [
    pytest.mark.skipif(HAS_GNUPG is False, reason="Needs python-gnupg library"),
    pytest.mark.skip_if_binaries_missing("gpg", reason="Needs gpg binary"),
]


@pytest.fixture
def gpghome(tmp_path):
    root = tmp_path / "gpghome"
    root.mkdir(mode=0o0700)
    try:
        yield root
    finally:
        # Make sure we don't leave any gpg-agents running behind
        gpg_connect_agent = shutil.which("gpg-connect-agent")
        if gpg_connect_agent:
            gnupghome = root / ".gnupg"
            if not gnupghome.is_dir():
                gnupghome = root
            try:
                subprocess.run(
                    [gpg_connect_agent, "killagent", "/bye"],
                    env={"GNUPGHOME": str(gnupghome)},
                    shell=False,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except subprocess.CalledProcessError:
                # This is likely CentOS 7 or Amazon Linux 2
                pass

        # If the above errored or was not enough, as a last resort, let's check
        # the running processes.
        for proc in psutil.process_iter():
            try:
                if "gpg-agent" in proc.name():
                    for arg in proc.cmdline():
                        if str(root) in arg:
                            proc.terminate()
            except Exception:  # pylint: disable=broad-except
                pass


@pytest.fixture
def gpg(loaders, states, gpghome):
    try:
        yield states.gpg
    finally:
        pass


@pytest.fixture
def key_a_fp():
    return "EF03765F59EE904930C8A781553A82A058C0C795"


@pytest.fixture
def key_a_pub():
    return """\
-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EY4fxHQEEAJvXEaaw+o/yZCwMOJbt5FQHbVMMDX/0YI8UdzsE5YCC4iKnoC3x
FwFdkevKj3qp+45iBGLLnalfXIcVGXJGACB+tPHgsfHaXSDQPSfmX6jbZ6pHosSm
v1tTixY+NTJzGL7hDLz2sAXTbYmTbXeE9ifWWk6NcIwZivUbhNRBM+KxABEBAAG0
LUtleSBBIChHZW5lcmF0ZWQgYnkgU2FsdFN0YWNrKSA8a2V5YUBleGFtcGxlPojR
BBMBCAA7FiEE7wN2X1nukEkwyKeBVTqCoFjAx5UFAmOH8R0CGy8FCwkIBwICIgIG
FQoJCAsCBBYCAwECHgcCF4AACgkQVTqCoFjAx5XURAQAguOwI+49lG0Kby+Bsyv3
of3GgxvhS1Qa7+ysj088az5GVt0pqVe3SbRVvn/jyC6yZvWuv94KdL3R7hCeEz2/
JakCRJ4wxEsdeASE8t9H/oTqD0I5asMa9EMvn5ICEGeLsTeQb7OYYihTQj7HJLG6
pDEmK8EhJDvV/9o0lnhm/9w=
=Wc0O
-----END PGP PUBLIC KEY BLOCK-----"""


@pytest.fixture
def key_a_sig():
    return """\
-----BEGIN PGP SIGNATURE-----

iLMEAAEIAB0WIQTvA3ZfWe6QSTDIp4FVOoKgWMDHlQUCY4fz7QAKCRBVOoKgWMDH
lYH/A/9iRT4JqzZEfRGM6XUyVbLCoF2xyEc43yL06nxn1sMFjMdLOLUDsaZbppHB
vEo4XJ45+Xqu1h3RK6bDVdDURyacPzdef8v357rJHjT8tb68JcwSzCBXLh29Nasl
cOm6/gNVIVm3Uoe9mKXESRvpMYmNUp2UM7ZzzBstK/ViVR82UA==
=EZPV
-----END PGP SIGNATURE-----"""


@pytest.fixture
def key_c_fp():
    return "96F136AC4C92D78DAF33105E35C03186001C6E31"


@pytest.fixture
def key_c_pub():
    return """\
-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EY4f2GgEEALToT23wZfLGM/JGCV4pWRlIXXqLwwEBSXral92HvsUjC8Vqsh1z
1n0K8/vIpS9OH2Q21emtht4y36rbahy+w6wRc1XXjPQ28Pyd+8v/jSKy/NKW3g+y
ZoB22vj4L35pAu/G6xs9+pKsLHGjMo+LsWZNEZ2Ar06aYA0dbTb0AqYfABEBAAG0
LUtleSBDIChHZW5lcmF0ZWQgYnkgU2FsdFN0YWNrKSA8a2V5Y0BleGFtcGxlPojR
BBMBCAA7FiEElvE2rEyS142vMxBeNcAxhgAcbjEFAmOH9hoCGy8FCwkIBwICIgIG
FQoJCAsCBBYCAwECHgcCF4AACgkQNcAxhgAcbjH2WAP/RtlUfN/novwmxxma6Zom
P6skFnCcRCs0vMU3OnNwuxZt9B+j0sUTu6noGi04Gcbd0eQs7v57DQHcRhNidZU/
8BJv5jD6E2yuzLK9lON+Yhgc6Pg6raA3hBeCY2HuzTEQLAThyV7ihboNILo7FJwo
y9KvnTFP2+oeDX2Z/m4SoWw=
=81Kb
-----END PGP PUBLIC KEY BLOCK-----"""


@pytest.fixture
def key_c_fail_sig():
    return """\
-----BEGIN PGP SIGNATURE-----

iLMEAAEIAB0WIQSW8TasTJLXja8zEF41wDGGABxuMQUCY4f2pwAKCRA1wDGGABxu
MdtOA/0ROhdh1VgfZn94PWgcrlurwYE0ftI3AXbSI00FsrWviF8WZQtp7YjrUC3t
/a/P1UYZkbBR0EeKwbKGmersq8mfif1qejWpQXpmmx011KQ0AFl7vdZUtcj2n454
KQE7MX8ePBchpSyhmvXzEezyw2FJp+YVOUKhDsc1vbNWTxGYJw==
=6tkK
-----END PGP SIGNATURE-----"""


@pytest.fixture
def gnupg(gpghome):
    return gnupglib.GPG(gnupghome=str(gpghome))


@pytest.fixture
def gnupg_keyring(gpghome, keyring):
    return gnupglib.GPG(gnupghome=str(gpghome), keyring=keyring)


@pytest.fixture(params=["ac"])
def pubkeys_present(gnupg, request):
    pubkeys = [request.getfixturevalue(f"key_{x}_pub") for x in request.param]
    fingerprints = [request.getfixturevalue(f"key_{x}_fp") for x in request.param]
    gnupg.import_keys("\n".join(pubkeys))
    present_keys = gnupg.list_keys()
    for fp in fingerprints:
        assert any(x["fingerprint"] == fp for x in present_keys)
    yield
    # cleanup is taken care of by gpghome and tmp_path


@pytest.fixture(params=["ac"])
def keyring(gpghome, tmp_path, request):
    keyring = tmp_path / "keys.gpg"
    _gnupg_keyring = gnupglib.GPG(gnupghome=str(gpghome), keyring=str(keyring))
    pubkeys = [request.getfixturevalue(f"key_{x}_pub") for x in request.param]
    fingerprints = [request.getfixturevalue(f"key_{x}_fp") for x in request.param]
    _gnupg_keyring.import_keys("\n".join(pubkeys))
    present_keys = _gnupg_keyring.list_keys()
    for fp in fingerprints:
        assert any(x["fingerprint"] == fp for x in present_keys)
    yield str(keyring)
    # cleanup is taken care of by gpghome and tmp_path


@pytest.fixture
def signed_data(tmp_path):
    signed_data = "What do you have if you have NaCl and NiCd? A salt and battery.\n"
    data = tmp_path / "signed_data"
    data.write_text(signed_data)
    assert data.read_bytes() == signed_data.encode()
    yield data
    data.unlink()


@pytest.fixture(params=["a"])
def sig(request, tmp_path):
    sigs = "\n".join(request.getfixturevalue(f"key_{x}_sig") for x in request.param)
    sig = tmp_path / "sig.asc"
    sig.write_text(sigs)
    yield str(sig)
    sig.unlink()


@pytest.mark.usefixtures("pubkeys_present")
def test_gpg_present_no_changes(gpghome, gpg, gnupg, key_a_fp):
    assert gnupg.list_keys(keys=key_a_fp)
    ret = gpg.present(
        key_a_fp[-16:], trust="unknown", gnupghome=str(gpghome), keyserver="nonexistent"
    )
    assert ret.result
    assert not ret.changes


def test_gpg_present_keyring_no_changes(
    gpghome, gpg, gnupg, gnupg_keyring, keyring, key_a_fp
):
    assert not gnupg.list_keys(keys=key_a_fp)
    assert gnupg_keyring.list_keys(keys=key_a_fp)
    ret = gpg.present(
        key_a_fp[-16:],
        trust="unknown",
        gnupghome=str(gpghome),
        keyserver="nonexistent",
        keyring=keyring,
    )
    assert ret.result
    assert not ret.changes


@pytest.mark.usefixtures("pubkeys_present")
def test_gpg_present_trust_change(gpghome, gpg, gnupg, key_a_fp):
    assert gnupg.list_keys(keys=key_a_fp)
    ret = gpg.present(
        key_a_fp[-16:],
        gnupghome=str(gpghome),
        trust="ultimately",
        keyserver="nonexistent",
    )
    assert ret.result
    assert ret.changes
    assert ret.changes == {key_a_fp[-16:]: {"trust": "ultimately"}}
    key_info = gnupg.list_keys(keys=key_a_fp)
    assert key_info
    assert key_info[0]["trust"] == "u"


def test_gpg_present_keyring_trust_change(
    gpghome, gpg, gnupg, gnupg_keyring, keyring, key_a_fp
):
    assert not gnupg.list_keys(keys=key_a_fp)
    assert gnupg_keyring.list_keys(keys=key_a_fp)
    ret = gpg.present(
        key_a_fp[-16:],
        gnupghome=str(gpghome),
        trust="ultimately",
        keyserver="nonexistent",
        keyring=keyring,
    )
    assert ret.result
    assert ret.changes
    assert ret.changes == {key_a_fp[-16:]: {"trust": "ultimately"}}
    key_info = gnupg_keyring.list_keys(keys=key_a_fp)
    assert key_info
    assert key_info[0]["trust"] == "u"


def test_gpg_absent_no_changes(gpghome, gpg, gnupg, key_a_fp):
    assert not gnupg.list_keys(keys=key_a_fp)
    ret = gpg.absent(key_a_fp[-16:], gnupghome=str(gpghome))
    assert ret.result
    assert not ret.changes


@pytest.mark.skip_unless_on_linux(
    reason="Complains about deleting private keys first when they are absent"
)
@pytest.mark.usefixtures("pubkeys_present")
def test_gpg_absent(gpghome, gpg, gnupg, key_a_fp):
    assert gnupg.list_keys(keys=key_a_fp)
    ret = gpg.absent(key_a_fp[-16:], gnupghome=str(gpghome))
    assert ret.result
    assert ret.changes
    assert "deleted" in ret.changes
    assert ret.changes["deleted"]


@pytest.mark.skip_unless_on_linux(
    reason="Complains about deleting private keys first when they are absent"
)
@pytest.mark.usefixtures("pubkeys_present")
def test_gpg_absent_from_keyring(gpghome, gpg, gnupg, gnupg_keyring, keyring, key_a_fp):
    assert gnupg.list_keys(keys=key_a_fp)
    assert gnupg_keyring.list_keys(keys=key_a_fp)
    ret = gpg.absent(key_a_fp[-16:], gnupghome=str(gpghome), keyring=keyring)
    assert ret.result
    assert ret.changes
    assert gnupg.list_keys(keys=key_a_fp)
    assert not gnupg_keyring.list_keys(keys=key_a_fp)


@pytest.mark.parametrize("keyring", [""], indirect=True)
def test_gpg_absent_from_keyring_delete_keyring(
    gpghome, gpg, gnupg, gnupg_keyring, keyring, key_a_fp
):
    assert not gnupg_keyring.list_keys()
    assert Path(keyring).exists()
    ret = gpg.absent(
        "abc", gnupghome=str(gpghome), keyring=keyring, keyring_absent_if_empty=True
    )
    assert ret.result
    assert ret.changes
    assert "removed" in ret.changes
    assert ret.changes["removed"] == keyring
    assert not Path(keyring).exists()


@pytest.mark.usefixtures("pubkeys_present")
def test_gpg_absent_test_mode_no_changes(gpghome, gpg, gnupg, key_a_fp):
    assert gnupg.list_keys(keys=key_a_fp)
    ret = gpg.absent(key_a_fp[-16:], gnupghome=str(gpghome), test=True)
    assert ret.result is None
    assert ret.changes
    assert "deleted" in ret.changes
    assert ret.changes["deleted"]
    assert gnupg.list_keys(keys=key_a_fp)


@pytest.mark.usefixtures("pubkeys_present")
@pytest.mark.parametrize(
    "sig,expected", [("a", True), (["c_fail"], False)], indirect=["sig"]
)
def test_gpg_verified(gpg, gnupg, gpghome, signed_data, sig, expected, key_a_fp):
    assert gnupg.list_keys(keys=key_a_fp)
    ret = gpg.verified(str(signed_data), gnupghome=str(gpghome), signature=sig)
    assert ret.result is expected
    assert not ret.changes


def test_gpg_verified_test_mode_no_pubkey(
    gpg, gnupg, gpghome, signed_data, sig, key_a_fp
):
    assert not gnupg.list_keys(keys=key_a_fp)
    ret = gpg.verified(
        str(signed_data), gnupghome=str(gpghome), signature=sig, test=True
    )
    assert ret.result is None
    assert not ret.changes


@pytest.mark.usefixtures("pubkeys_present")
def test_gpg_verified_test_mode_no_signed_data(
    gpg, gnupg, gpghome, sig, tmp_path, key_a_fp
):
    assert gnupg.list_keys(keys=key_a_fp)
    ret = gpg.verified(
        str(tmp_path / "file"), gnupghome=str(gpghome), signature=sig, test=True
    )
    assert ret.result is None
    assert not ret.changes


@pytest.mark.usefixtures("pubkeys_present")
def test_gpg_verified_test_mode_no_signature(
    gpg, gnupg, gpghome, signed_data, tmp_path, key_a_fp
):
    assert gnupg.list_keys(keys=key_a_fp)
    ret = gpg.verified(
        str(signed_data),
        gnupghome=str(gpghome),
        signature=str(tmp_path / "sig"),
        test=True,
    )
    assert ret.result is None
    assert not ret.changes
