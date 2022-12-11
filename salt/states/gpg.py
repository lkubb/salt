"""
Manage GPG keychains
====================

.. versionadded:: 2016.3.0

"""

import logging

import salt.utils.dictupdate
from salt.exceptions import SaltInvocationError

log = logging.getLogger(__name__)

TRUST_MAP = {
    "expired": "Expired",
    "unknown": "Unknown",
    "not_trusted": "Not Trusted",
    "marginally": "Marginally",
    "fully": "Fully Trusted",
    "ultimately": "Ultimately Trusted",
}


def present(
    name,
    keys=None,
    user=None,
    keyserver=None,
    gnupghome=None,
    trust=None,
    keyring=None,
    **kwargs,
):
    """
    Ensure a GPG public key is present in the GPG keychain.

    name
        The key ID of the GPG public key.

    keys
        The key ID or key IDs to add to the GPG keychain.

    user
        Add GPG keys to the specified user's keychain.

    keyserver
        The keyserver to retrieve the keys from.

    gnupghome
        Override GnuPG home directory.

    trust
        Trust level for the key in the keychain,
        ignored by default. Valid trust levels:
        expired, unknown, not_trusted, marginally,
        fully, ultimately

    keyring
        Limit the operation to this specific keyring, specified as
        a local filesystem path.

        .. versionadded:: 3007.0
    """

    ret = {"name": name, "result": True, "changes": {}, "comment": []}

    _current_keys = __salt__["gpg.list_keys"](
        user=user, gnupghome=gnupghome, keyring=keyring
    )

    current_keys = {}
    for key in _current_keys:
        keyid = key["keyid"]
        current_keys[keyid] = {}
        current_keys[keyid]["trust"] = key["trust"]

    if not keys:
        keys = name

    if isinstance(keys, str):
        keys = [keys]

    for key in keys:
        if key in current_keys:
            if trust:
                if trust in TRUST_MAP:
                    if current_keys[key]["trust"] != TRUST_MAP[trust]:
                        if __opts__["test"]:
                            ret["result"] = None
                            ret["comment"].append(
                                f"Would have set trust level for {key} to {trust}"
                            )
                            salt.utils.dictupdate.set_dict_key_value(
                                ret, f"changes:{key}:trust", trust
                            )
                            continue
                        try:
                            # update trust level
                            result = __salt__["gpg.trust_key"](
                                keyid=key,
                                trust_level=trust,
                                user=user,
                                gnupghome=gnupghome,
                                keyring=keyring,
                            )
                        except SaltInvocationError as err:
                            result = {"res": False, "message": str(err)}
                        if result["res"] is False:
                            ret["result"] = result["res"]
                            ret["comment"].append(result["message"])
                        else:
                            salt.utils.dictupdate.set_dict_key_value(
                                ret, f"changes:{key}:trust", trust
                            )
                            ret["comment"].append(
                                f"Set trust level for {key} to {trust}"
                            )
                    else:
                        ret["comment"].append(
                            f"GPG Public Key {key} already in correct trust state"
                        )
                else:
                    ret["comment"].append(f"Invalid trust level {trust}")

            ret["comment"].append(f"GPG Public Key {key} already in keychain")

        else:
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"].append(f"Would have added {key} to GPG keychain")
                salt.utils.dictupdate.set_dict_key_value(
                    ret, f"changes:{key}:added", True
                )
                continue
            result = __salt__["gpg.receive_keys"](
                keyserver=keyserver,
                keys=key,
                user=user,
                gnupghome=gnupghome,
                keyring=keyring,
            )
            if result["res"] is False:
                ret["result"] = result["res"]
                ret["comment"].extend(result["message"])
            else:
                ret["comment"].append(f"Added {key} to GPG keychain")
                salt.utils.dictupdate.set_dict_key_value(
                    ret, f"changes:{key}:added", True
                )

            if trust:
                if trust in TRUST_MAP:
                    try:
                        # update trust level
                        result = __salt__["gpg.trust_key"](
                            keyid=key,
                            trust_level=trust,
                            user=user,
                            gnupghome=gnupghome,
                            keyring=keyring,
                        )
                    except SaltInvocationError as err:
                        result = {"res": False, "message": str(err)}
                    if result["res"] is False:
                        ret["result"] = result["res"]
                        ret["comment"].append(result["message"])
                    else:
                        ret["comment"].append(f"Set trust level for {key} to {trust}")
                else:
                    ret["comment"].append(f"Invalid trust level {trust}")

    ret["comment"] = "\n".join(ret["comment"])
    return ret


def absent(
    name,
    keys=None,
    user=None,
    gnupghome=None,
    keyring=None,
    keyring_absent_if_empty=False,
    **kwargs,
):
    """
    Ensure a GPG public key is absent from the keychain.

    name
        The key ID of the GPG public key.

    keys
        The key ID or key IDs to remove from the GPG keychain.

    user
        Remove GPG keys from the specified user's keychain.

    gnupghome
        Override GnuPG home directory.

    keyring
        Limit the operation to this specific keyring, specified as
        a local filesystem path.

        .. versionadded:: 3007.0

    keyring_absent_if_empty
        Make sure to not leave behind an empty keyring file
        if ``keyring`` was specified. Defaults to false.

        .. versionadded:: 3007.0
    """

    ret = {"name": name, "result": True, "changes": {}, "comment": []}

    _current_keys = __salt__["gpg.list_keys"](
        user=user, gnupghome=gnupghome, keyring=keyring
    )

    current_keys = []
    for key in _current_keys:
        current_keys.append(key["keyid"])

    if not keys:
        keys = name

    if isinstance(keys, str):
        keys = [keys]

    for key in keys:
        if key in current_keys:
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"].append(f"Would have deleted {key} from GPG keychain")
                salt.utils.dictupdate.append_dict_key_value(ret, "changes:deleted", key)
                continue
            result = __salt__["gpg.delete_key"](
                keyid=key,
                user=user,
                gnupghome=gnupghome,
                keyring=keyring,
            )
            if result["res"] is False:
                ret["result"] = result["res"]
                ret["comment"].append(result["message"])
            else:
                ret["comment"].append(f"Deleted {key} from GPG keychain")
                salt.utils.dictupdate.append_dict_key_value(ret, "changes:deleted", key)
        else:
            ret["comment"].append(f"{key} not found in GPG keychain")

    if __opts__["test"] or not ret["result"]:
        return ret

    _new_keys = [
        x["keyid"]
        for x in __salt__["gpg.list_keys"](
            user=user, gnupghome=gnupghome, keyring=keyring
        )
    ]

    if set(keys) & set(_new_keys):
        remaining = set(keys) & set(_new_keys)
        ret["result"] = False
        ret["comment"].append(
            "State check revealed the following keys could not be deleted: "
            + ", ".join(remaining)
        )
        ret["changes"]["deleted"] = list(
            set(ret["changes"]["deleted"]) - set(_new_keys)
        )

    elif (
        not _new_keys
        and keyring
        and keyring_absent_if_empty
        and __salt__["file.file_exists"](keyring)
    ):
        __salt__["file.remove"](keyring)
        ret["comment"].append(f"Removed empty keyring file {keyring}")
        ret["changes"]["removed"] = keyring

    ret["comment"] = "\n".join(ret["comment"])
    return ret


def verified(
    name,
    signature=None,
    trustmodel=None,
    signed_by_any=None,
    signed_by_all=None,
    user=None,
    gnupghome=None,
    keyring=None,
):
    """
    Ensure a file signature is valid.

    This is intended to provide a simple and explicit interface to
    verify signatures for states, but does not actually modify anything.

    You can act on the result of this state with ``onfail``/``require``
    requisites in subsequent states.

    .. versionadded:: 3007.0

    name
        Path to the file to verify. Required.

    signature
        Path to a detached signature.

    trustmodel
        Explicitly define the used trust model. One of:
          - pgp
          - classic
          - tofu
          - tofu+pgp
          - direct
          - always
          - auto

    user
        Run GPG as this user. Defaults to Salt process user.
        Passing the user as ``salt`` will set the GnuPG home directory to
        ``/etc/salt/gpgkeys``.

    gnupghome
        Override GnuPG home directory.

    keyring
        Limit the operation to this specific keyring, specified as
        a local filesystem path.

    signed_by_any
        A list of key fingerprints from which any valid signature
        will mark verification as passed. If none of the provided
        keys signed the data, verification will fail. Optional.
        Note that this does not take into account trust.

    signed_by_all
        A list of key fingerprints whose signatures are required
        for verification to pass. If a single provided key did
        not sign the data, verification will fail. Optional.
        Note that this does not take into account trust.

    """
    ret = {"name": name, "result": False, "changes": {}, "comment": []}
    try:
        res = __salt__["gpg.verify"](
            filename=name,
            signature=signature,
            trustmodel=trustmodel,
            signed_by_any=signed_by_any,
            signed_by_all=signed_by_all,
            user=user,
            gnupghome=gnupghome,
            keyring=keyring,
        )
    except FileNotFoundError as err:
        res = {"res": False, "message": str(err)}
    if not res["res"] and __opts__["test"]:
        ret["result"] = None
        ret["comment"] = (
            "Could not verify file. Not failing because test mode is active. "
            "You can ignore this message if you create files necessary files and "
            "import necessary keys. Falure was:\n" + res["message"]
        )
        return ret
    ret["result"] = res["res"]
    ret["comment"] = res["message"]
    return ret
