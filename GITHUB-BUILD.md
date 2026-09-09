# GitHub Actions build instructions

This repository is prepared to build the RootHide Inject Analysis integration entirely on GitHub Actions.
No local Theos/iPhoneOS SDK/ldid installation is required.

## What is pinned

- RootHide baseline: `Baseline/com.roothide.manager_1.3.9+bindtrust1.deb`
- Analysis source: 1.0.17
- Architectures: arm64 + arm64e
- Deployment target: iOS 15.0+
- Injection load: `LC_LOAD_WEAK_DYLIB @executable_path/Frameworks/RCInjectAnalysis.dylib`

The release pipeline refuses a baseline whose SHA/metadata do not match the analyzed RootHide package.

## Push with Git Bash

From the extracted repository directory:

```bash
git init
git branch -M main
git add .
git commit -m "Build RootHide Inject Analysis 1.0.17"
git remote add origin https://github.com/YOUR_NAME/YOUR_REPOSITORY.git
git push -u origin main
```

If the repository already exists locally, just copy/replace the files and use your normal `git add`, `git commit`, `git push` flow.

## Build

A push to `main` automatically runs `.github/workflows/build.yml`.
You can also run it manually from GitHub -> Actions -> Build RootHide Inject Analysis -> Run workflow.

The workflow uses a GitHub macOS runner with Xcode's real iPhoneOS SDK, installs Theos, `ldid`, and `dpkg`, builds arm64 + arm64e, signs the dylib, preserves the original RootHide entitlements, patches the Manager weak-load command, repacks the deb, and runs the existing release gates.

## Download

On a successful run, open the workflow run -> Artifacts and download:

`RCInjectAnalysis-RootHideBlacklist-1.0.17-<run number>`

The artifact should contain the final `+analysis1.0.17.deb`, release receipt, source provenance, build-source snapshot, and deployment kit.

If the job fails, download `RCInjectAnalysis-build-log-<run number>` and provide the log for diagnosis.

## Important

A green GitHub build proves the actual iOS compile/sign/package static pipeline passed. The resulting deb still needs the RootHide device runtime checks in `FIRST-RUN-TEST.md` before treating it as stable.
