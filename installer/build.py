import PyInstaller.__main__

PyInstaller.__main__.run(["capybara-encrypt.py", "--onefile", "--icon=favicon.ico"])
PyInstaller.__main__.run(["capybara-decrypt.py", "--onefile", "--icon=favicon.ico"])