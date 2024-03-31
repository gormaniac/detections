# Yara Rules

Some of these rules have been uploaded to the Triage Sandbox ([tria.ge](https://tria.ge/)) and have special meta values to support this.

## Naming Convention

`(Platform_)FileType/Category(_MalwareType)_DetectionDetails(_Identifier)`

- `Platform` is an optional string identifying the OS platform the rule detects files on.
    - Capitalized
- `FileType/Category` is either a file extension or a more generic (abbreviated) category of files.
    - Capitalized
- `MalwareType` optionally identify the type of Malware the rule detects.
    - Will be `Hunting` if the rule looks for more generic behaviors rather than specific malware.
- `DetectionDetails` describe what the rule specifically looks for.
    - This may be a Malware Family name.
    - Multiple strings are separated by an underscore.
- `Identifier` if more than one rule would end up with the same name, optionally use a unique identifer appeneded to the end of the rule.
    - Usually just an integer.
