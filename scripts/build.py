import hashlib
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
source = ROOT / "中兴微固件工具箱.py"
target = sys.argv[1]
name = "zxw-firmware-toolbox"
windows = sys.platform == "win32"
mac = sys.platform == "darwin"
expected = {"windows-x64": ("win32", 64), "windows-legacy-x86": ("win32", 32),
            "linux-x64": ("linux", 64), "macos-arm64": ("darwin", 64)}
assert (sys.platform, struct.calcsize("P") * 8) == expected[target]
if mac:
    assert platform.machine() == "arm64"

stage = ROOT / "ci-build"
stage.mkdir(exist_ok=True)
launcher = stage / "launcher.py"
launcher.write_text("""import os
import sys
import 中兴微固件工具箱 as app

if getattr(sys, 'frozen', False) and sys.platform != 'darwin':
    app.BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
if sys.argv[1:] == ['--ci-smoke']:
    import lz4.block
    import zstandard
    from pathlib import Path
    from PyQt5.QtCore import QSettings
    QSettings.setDefaultFormat(QSettings.IniFormat)
    QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, os.getcwd())
    qt = app.QApplication([])
    window = app.MainWindow()
    window.show_support()
    dialog = window._support_dialog
    assert dialog is not None and dialog.channel == 'wechat'
    dialog.channel_buttons['alipay'].click()
    assert dialog.channel == 'alipay' and not dialog.qr_label.pixmap().isNull()
    window.close()
    Path('smoke.ok').write_text('ok', encoding='utf-8')
elif len(sys.argv) > 1 and sys.argv[1] == '--cli':
    sys.exit(app.cli_main(sys.argv[2:]))
else:
    app.main()
""", encoding="utf-8")
shutil.copyfile(source, stage / source.name)

env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--noupx", "--name", name,
       "--distpath", str(stage / "dist"), "--workpath", str(stage / "work"),
       "--specpath", str(stage)]
cmd += ["--onedir", "--windowed"] if mac else ["--onefile"]
if windows:
    cmd += ["--windowed"]
    icon_script = """import struct
import sys
from pathlib import Path
import 中兴微固件工具箱 as app
from PyQt5.QtCore import QByteArray, QBuffer, QIODevice
qt = app.QApplication([])
icon = app.create_app_icon()
images = []
for size in (16, 24, 32, 48, 64, 128, 256):
    data = QByteArray()
    buf = QBuffer(data)
    assert buf.open(QIODevice.WriteOnly)
    assert icon.pixmap(size, size).save(buf, 'PNG')
    images.append((size, bytes(data)))
offset = 6 + 16 * len(images)
header = bytearray(struct.pack('<HHH', 0, 1, len(images)))
for size, data in images:
    header.extend(struct.pack('<BBBBHHII', size % 256, size % 256, 0, 0, 1, 32, len(data), offset))
    offset += len(data)
Path(sys.argv[1]).write_bytes(header + b''.join(data for _, data in images))
"""
    icon_generator = stage / "make_icon.py"
    icon_generator.write_text(icon_script, encoding="utf-8")
    icon_path = stage / "generated.ico"
    subprocess.run([sys.executable, str(icon_generator), str(icon_path)], env=env, check=True)
    cmd += ["--icon", str(icon_path)]
for module in ("argparse", "base64", "datetime", "functools", "hashlib", "io",
               "json", "lz4.block", "lzma", "math", "os", "re", "shutil", "stat",
               "struct", "sys", "tempfile", "time", "uuid", "zlib", "zstandard",
               "ctypes", "ctypes.wintypes", "zstandard.backend_c"):
    cmd += ["--hidden-import", module]
subprocess.run(cmd + [str(launcher)], check=True)
dist = stage / "dist"
item = dist / (name + (".app" if mac else ".exe" if windows else ""))
binary = item / "Contents/MacOS" / name if mac else item
marker = stage / "smoke.ok"
if marker.exists():
    marker.unlink()
subprocess.run([str(binary), "--ci-smoke"], cwd=stage, env=env, check=True, timeout=120)
assert marker.read_text(encoding="utf-8") == "ok"
subprocess.run([str(binary), "--cli", "--help"], cwd=stage, env=env, check=True, timeout=120)

output = ROOT / "packages"
output.mkdir(exist_ok=True)
archive = output / (name + "-" + target + (".tar.gz" if target == "linux-x64" else ".zip"))
if mac:
    subprocess.run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(item), str(archive)], check=True)
elif windows:
    import zipfile
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(item, item.name)
        if target == "windows-legacy-x86":
            z.writestr("Windows7-SP1.txt", "Windows 7 SP1 is a compatibility target, not CI-tested. If Universal CRT is missing, see https://support.microsoft.com/help/2999226\n")
else:
    import tarfile
    with tarfile.open(archive, "w:gz") as t:
        t.add(item, arcname=item.name)
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
Path(str(archive) + ".sha256").write_bytes(f"{digest}  {archive.name}\n".encode("ascii"))
