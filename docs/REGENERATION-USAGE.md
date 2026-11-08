# Export a captured application workspace

**Status, 2026-10-27:** This is a bounded, captured-workspace
AppleScript export of an editable **nonfunctional Xcode skeleton**,
not complete source recovery or behaviorally equivalent app regeneration.
The latest [source-status snapshot](STATUS.md) does not claim native or
installed acceptance for this bridge. See [Capabilities](CAPABILITIES.md).

The `export-project` scripting command exports the selected, already-analyzed macOS arm64 application into a new directory. It preserves the captured analysis identity and does not reopen or reanalyze the executable. The supplied bundle path provides current passive resource and Info.plist observations. These observations are not proven to belong to the earlier captured executable: a bundle may have been replaced at the same path. The manifest records `resourceProvenance.captureBasis = currentBundlePath` and `imageBinding = unassessed`; the observed plist is preserved as `Support/ObservedBundleInfo.plist`.

With the application's captured workspace active in MacScope, invoke its dedicated AppleScript command from Terminal:

```applescript
tell application "MacScope"
    run command command "export-project" with arguments {appPath:"/Applications/Example.app", outputDirectory:"/absolute/path/to/new/ExampleExport"}
end tell
```

Replace both paths. The destination's parent must exist, and the destination itself must not exist. An optional `image` argument selects the loaded image slot or image-owner UUID; otherwise the primary image is selected. The selected executable must belong to the supplied application bundle.

The result reports the generated Xcode project, `REGEN-MANIFEST.json`, conversion diagnostics, function and resource counts, and retained tool-log directory. Existing destinations are never replaced. A failed export retains an incomplete staging directory for diagnosis.

Every discovered function has a manifest entry and a nonfunctional stub. Recovered declarations, original metadata and dependent-library names remain available for editing and review. Building this skeleton does not recover the original application's behavior and does not promote a function from `stub` to `compiles` or `accepted`.

Localization and supported Core Data models are compiled back and compared before their editable sources are selected for the generated build. A successful comparison certifies only the currently read resource bytes; it does not bind them to the historical captured image or establish function equivalence. Unsupported or failed conversions retain the original compiled resources. Asset catalogs and nibs currently retain compiled fallback in this first integrated increment.

The generated target disables signing and does not apply recovered entitlements automatically. The exported app is not executed by the exporter. General MCP does not expose `export-project`; the legacy `--run-script` path refuses it before binary loading. Use the captured-workspace scripting bridge above.

Qualification: isolated generated mixed C/Objective-C/Swift skeleton compilation and first localization/Core Data compile-back receipts are described in the integration record for their named inputs. Production integration compilation, first live Apple-event dispatch, and full native runtime acceptance must be recorded separately; this usage description is not evidence that those checks passed.

## Signature-assisted C body import

New exports include `C-BODY-REQUEST.json`, carrying the image identity and eligible
function coordinates already captured by the workspace. The producer API and
source-evidence requirements are documented in `Scripts/compilable-c-export/README.md`.
Optional `cBodiesPath` on `export-project` admits the resulting bounded JSON packet.
Missing or mismatched identity leaves the original stub intact. A matching body is
stored exactly, with the original placeholder preserved, and marked `filled` only.
The reply reports actual `stubCount` and `filledCount`. No caller-supplied status
establishes compilation, execution equivalence, or Reconstruction acceptance.
