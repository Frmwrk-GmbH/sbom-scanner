# ADR-001: Multi-SBOM-Format Support (CycloneDX + SPDX)

**Status:** Proposed  
**Date:** 2026-03-22  
**Context:** Feature request to support SPDX alongside CycloneDX

## Problem

The codebase is currently hardcoded to CycloneDX 1.6. There is interest in supporting SPDX as an alternative SBOM output format.

## Coupling Analysis

### Format-agnostic (no changes needed)

| Layer | Files | Notes |
|---|---|---|
| Ecosystem parsing | `detect()`, `parse()`, `fetch_latest_versions()` | Return generic dicts |
| PURL identifiers | All ecosystems | Standard across formats |
| Scanner plugins | grype.py, osv.py | Work with both formats |
| Configurator | configure.py | Doesn't touch SBOM format |
| CLI routing | cli.py | Format-agnostic |

### CycloneDX-coupled

| Layer | Files | Coupling |
|---|---|---|
| `build_component()` | 6 ecosystem files | Returns CycloneDX dict: `bom-ref`, `scope`, `externalReferences`, `properties[{name,value}]` |
| BOM assembly | generate_sbom.py | `bomFormat`, `specVersion`, `metadata.tools`, `dependencies[{ref,dependsOn}]` |
| Data processing | report_data.py | `get_prop()` reads `properties` array, `classify_components()` uses `cdx:ecosystem`, `build_dep_lookup()` reads CycloneDX `dependencies` |
| Renderers | html.py, simple_html.py, json_report.py, csv_report.py | All depend on report_data.py |

## Options

### Option A: Formatter layer (clean, high effort)

Ecosystems return format-agnostic component dicts. A new `formatters/` module converts to CycloneDX or SPDX.

```
formatters/
  base.py        # SbomFormatter ABC
  cyclonedx.py   # Current logic extracted
  spdx.py        # New
```

- **Pros:** Clean architecture, SPDX as first-class citizen
- **Cons:** High impact across the entire codebase:
  - All 6 ecosystem `build_component()` methods must change return format
  - `report_data.py` must be rewritten to support a generic component model
  - All 5 renderers depend on `report_data.py` and need adaptation
  - `generate_sbom.py` BOM assembly completely rewritten
  - Existing tests break and must be rewritten
  - External ecosystem plugins (by contributors) would also break
  - Risk of regressions across all output formats and the dependency tree
- **Effort:** Very high — estimated 2-3 days of focused refactoring + testing
- **When warranted:** Only if SPDX needs to be a first-class internal format
  (e.g. reading external SPDX SBOMs, SPDX-native report rendering)

### Option B: Post-processing converter (pragmatic, low effort)

Keep CycloneDX as internal format. Add SPDX as a conversion step at the output layer.

```python
# generate_sbom.py
bom = build_cyclonedx_bom(...)
if format == "spdx":
    bom = cyclonedx_to_spdx(bom)
```

- **Pros:** Zero changes to ecosystem modules, scanners, renderers, configurator, tests
- **Cons:** CycloneDX remains internal model, SPDX is second-class
- **Effort:** 1 new file + 1 modified file
- **Risk:** Low

### Option C: Dual build_component()

Add `build_component_generic()` to base class. Existing `build_component()` becomes a CycloneDX wrapper. Gradual migration.

- **Pros:** Backward compatible, incremental
- **Cons:** Two methods to maintain
- **Effort:** Medium

## Decision

**Recommended: Option B** (post-processing converter) for initial SPDX support.

Rationale:
- Zero impact on existing ecosystem plugins — critical since external contributors may add ecosystems
- The report layer always consumes CycloneDX internally — renderers don't need to change
- SPDX output is achievable with a single converter function
- Libraries like `cyclonedx-python-lib` or manual mapping can handle conversion
- If SPDX becomes a first-class requirement later, Option A can be implemented as a follow-up

## Option B: Implications of CycloneDX-as-internal + SPDX converter

### Works well for
- Compliance requirements that mandate SPDX output (deliver the converted file)
- CI/CD pipelines that expect SPDX as input
- Toolchains that only read SPDX (e.g. legal/procurement tools)

### Limitations
- **SPDX properties lost** — CycloneDX has `properties[{name,value}]`, SPDX has no equivalent.
  All `cdx:*` metadata (dep_type, module, latest version) cannot be transferred 1:1.
- **Relationship types flattened** — SPDX has richer relationship types
  (`DEPENDS_ON`, `BUILD_DEPENDENCY_OF`, `DEV_DEPENDENCY_OF`, `OPTIONAL_DEPENDENCY_OF`).
  A conversion from CycloneDX flattens everything to `DEPENDS_ON` because CycloneDX only
  distinguishes dependency types via properties.
- **License expressions** — SPDX uses SPDX expressions (`MIT AND Apache-2.0`),
  CycloneDX uses a list. Conversion is possible but not lossless for complex dual-license scenarios.
- **No roundtrip** — CycloneDX → SPDX → CycloneDX loses information.
- **Report layer untouched** — Reports always read CycloneDX internally, regardless of export format.
  SPDX SBOMs from other tools cannot be used as input for `sbom report`.

### Conclusion
- **For output:** Conversion is sufficient.
- **For input (reading external SBOMs):** Option A (formatter layer) would be needed.

## Implementation (when needed)

1. Add `--sbom-format cyclonedx|spdx` flag to `sbom scan`
2. Create `formatters/spdx.py` with `cyclonedx_to_spdx(bom: dict) -> dict`
3. Call converter in `generate_sbom.py` before writing output
4. Default remains `cyclonedx`

## Key SPDX differences

| Aspect | CycloneDX | SPDX |
|---|---|---|
| Root | `bomFormat: CycloneDX` | `spdxVersion: SPDX-2.3` |
| Packages | `components[]` | `packages[]` |
| IDs | `bom-ref` (PURL) | `SPDXID: SPDXRef-...` |
| Dependencies | `dependencies[{ref, dependsOn}]` | `relationships[{spdxElementId, relationshipType, relatedSpdxElement}]` |
| Licenses | `licenses[{license: {id}}]` | `licenseConcluded` (SPDX expression) |
| Properties | `properties[{name, value}]` | Annotations or no equivalent |

## References

- [CycloneDX 1.6 Spec](https://cyclonedx.org/docs/1.6/json/)
- [SPDX 2.3 Spec](https://spdx.github.io/spdx-spec/v2.3/)
- [cyclonedx-python-lib](https://github.com/CycloneDX/cyclonedx-python-lib)
