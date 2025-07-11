from __future__ import annotations

import hashlib

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.pe import PE
from tests._utils import absolute_path


def test_resource() -> None:
    """Test the resource directory."""
    with absolute_path("_data/pe/64/comres.dll").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "ARM64"
        assert pe.resources

        # Test the raw tree first
        assert list(pe.resources.tree.listdir().keys()) == ["MUI", 16]
        assert list(pe.resources.tree.get("MUI").listdir().keys()) == [1]
        assert list(pe.resources.tree.get("MUI").get(1).listdir().keys()) == [1033]
        assert pe.resources.tree.get("MUI").get(1).get(1033).address == 0x7080
        assert pe.resources.tree.get("MUI").get(1).get(1033).size == 280
        assert (
            hashlib.sha1(pe.resources.tree.get("MUI").get(1).get(1033).data).hexdigest()
            == "eeee31518d39d8234ec870d0c3a7eba0eebd728d"
        )

        # Test the higher level API
        assert len(list(pe.resources)) == 2
        assert len(pe.resources["MUI"]) == 1
        assert pe.resources["MUI"][0].name == 1
        assert pe.resources["MUI"][0].languages() == ["en-US"]
        assert hashlib.sha1(pe.resources["MUI"][0].data()).hexdigest() == "eeee31518d39d8234ec870d0c3a7eba0eebd728d"

        assert pe.resources.vs_version_info() == {
            "VS_VERSION_INFO": {
                "FileVersion": "2001.12.10941.16384",
                "ProductVersion": "10.0.22621.1",
                "FileOS": "NT_WINDOWS32",
                "FileType": "DLL",
                "StringFileInfo": {
                    "en-US_utf-16": {
                        "CompanyName": "Microsoft Corporation",
                        "FileDescription": "COM+ Resources",
                        "FileVersion": "2001.12.10941.16384 (WinBuild.160101.0800)",
                        "InternalName": "COMRES.DLL",
                        "LegalCopyright": "© Microsoft Corporation. All rights reserved.",
                        "OriginalFilename": "COMRES.DLL",
                        "ProductName": "Microsoft® Windows® Operating System",
                        "ProductVersion": "10.0.22621.1",
                    }
                },
                "VarFileInfo": {"Translation": ["en-US_utf-16"]},
            }
        }


def test_resource_accelerator_table() -> None:
    """Test the accelerator resource parsing."""
    with absolute_path("_data/pe/32/PUNZIP.EXE").open("rb") as fh:
        pe = PE(fh)

        assert pe.resources.accelerator_table() == [
            (c_pe.VK.A, 40009, c_pe.ACCEL_F.VIRTKEY | c_pe.ACCEL_F.NOINVERT | c_pe.ACCEL_F.CONTROL),
            (c_pe.VK.E, 40004, c_pe.ACCEL_F.VIRTKEY | c_pe.ACCEL_F.NOINVERT | c_pe.ACCEL_F.CONTROL),
            (c_pe.VK.O, 40001, c_pe.ACCEL_F.VIRTKEY | c_pe.ACCEL_F.NOINVERT | c_pe.ACCEL_F.CONTROL),
            (c_pe.VK.T, 40006, c_pe.ACCEL_F.VIRTKEY | c_pe.ACCEL_F.NOINVERT | c_pe.ACCEL_F.CONTROL),
            (c_pe.VK.RETURN, 40008, c_pe.ACCEL_F.VIRTKEY | c_pe.ACCEL_F.NOINVERT),
            (c_pe.VK.RETURN, 40002, c_pe.ACCEL_F.VIRTKEY | c_pe.ACCEL_F.NOINVERT | c_pe.ACCEL_F.ALT),
        ]


def test_resource_string_table() -> None:
    """Test the string table resource parsing."""
    with absolute_path("_data/pe/32/TpmCertResources.dll").open("rb") as fh:
        pe = PE(fh)

        assert pe.resources.string_table() == {
            7673: "https://ekop.intel.com/ekcertservice",
            9298: "http://127.0.0.1:27015/EkCertService",
            33224: "https://ekcert.spserv.microsoft.com/EKCertificate/GetEKCertificate/v1",
            58380: "http://ftpm.amd.com/pki/aia",
            59629: "https://ekcert.spserv.microsoft.com/EKCertificate/GetEKCertificate/v1",
        }
