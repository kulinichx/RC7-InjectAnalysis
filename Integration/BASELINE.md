# Verified RootHide baseline

Input package:

```text
Package: com.roothide.manager
Version: 1.3.9+bindtrust1
Architecture: iphoneos-arm64e
Executable: /Applications/RootHide.app/RootHide
```

Full input deb SHA-256:

```text
5392005d50c2a3e6189545e408aa4723bad401995ec508efcb48010c53d57f28
```

Pinned tar-header ownership model:

```text
numeric uid: 501
numeric gid: 20
uname: root
gname: wheel
```

This intentionally preserves the original package headers rather than normalizing through the build host. The unchanged `postinst` later applies `chown 0:0` + `chmod +s` specifically to the installed RootHide executable.

Main executable SHA-256:

```text
c12b596acd1856677b8fb9753fcebdd88c7601318f10b6b7a8926e2568de687e
```

Static load-command patch test:

```text
arm64:
  before ncmds: 32
  after ncmds:  33
  after sizeofcmds: 4256
  first section offset: 0x8000
  new load command size: 80
  remaining header padding after insertion: 28480 bytes

arm64e:
  before ncmds: 32
  after ncmds:  33
  after sizeofcmds: 4336
  first section offset: 0x4000
  new load command size: 80
  remaining header padding after insertion: 12016 bytes
```

Verified load path in both slices:

```text
@executable_path/Frameworks/RCInjectAnalysis.dylib (weak)
```

Original RootHide XML entitlement plist extraction produced 199 keys. The packaging script extracts entitlements again from the input executable instead of blindly trusting the bundled reference copy.

Original package `postinst` remains unchanged:

```sh
uicache -p /Applications/RootHide.app
chown 0:0 /Applications/RootHide.app/RootHide
chmod +s /Applications/RootHide.app/RootHide
```
