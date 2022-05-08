# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


a = Analysis(['server_gui.py'],
             pathex=[],
             binaries=[],
             datas=[( '/home/hsarode/Desktop/gitlab stuff/f21cn-f20cn-2021-22-cw2-master/server_gui_test/src/caCertificate.cer', '.' ),
			( '/home/hsarode/Desktop/gitlab stuff/f21cn-f20cn-2021-22-cw2-master/server_gui_test/src/server.cer', '.' ),
			( '/home/hsarode/Desktop/gitlab stuff/f21cn-f20cn-2021-22-cw2-master/server_gui_test/src/serverKey.pem', '.' )
		   ],
             hiddenimports=[],
             hookspath=[],
             hooksconfig={},
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,  
          [],
          name='server_gui',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True,
          disable_windowed_traceback=False,
          target_arch=None,
          codesign_identity=None,
          entitlements_file=None )
