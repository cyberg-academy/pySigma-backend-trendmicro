# pySigma-backend-trendmicro
![Status](https://img.shields.io/badge/Status-alpha-yellow)

# pySigma TrendMicro Backend

This is the TrendMicro backend for pySigma. It provides the package `sigma.backends.trendmicro` with the `TrendMicroBackend` class.
Further, it contains the processing pipelines in `sigma.pipelines.trendmicro` for field renames and error handling. This pipeline is automatically applied to `SigmaRule` and `SigmaCollection` objects passed to the `TrendMicroBackend` class.

It supports the following output formats:

* default: plain TrendMicro queries

This backend is currently maintained by:

* [Pepe Llopis](https://github.com/cyberg-academy)

## Usage

### pySigma
```python
from sigma.backends.trendmicro import TrendmicroVisionOneBackend
from sigma.rule import SigmaRule

rule = SigmaRule.from_yaml("""
title: Invoke-Mimikatz CommandLine
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine|contains: Invoke-Mimikatz
    condition: sel""")


backend = TrendmicroVisionOneBackend()
print(backend.convert_rule(rule)[0])
```

## Side Notes & Limitations
- Backend uses [TrendMicro VisionOne query syntax](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-search-syntax)
- Pipeline uses TrendMicro field names
- Pipeline supports `linux`, `windows`, and `macos` product types
- Pipeline supports the following category types for field mappings
  - `process_creation`
  - `file_event`
  - `file_change`
  - `file_rename`
  - `file_delete`
  - `image_load`
  - `pipe_creation`
  - `registry_add`
  - `registry_delete`
  - `registry_event`
  - `registry_set`
  - `dns_query`
  - `dns`
  - `network_connection`
  - `firewall`
- Any unsupported fields or categories will throw errors
