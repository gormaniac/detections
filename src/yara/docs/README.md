# Rules for Document Files

"Document" in this case means common file types meant for human consumption of information. This includes all Microsoft document formats, PDFs, RTFs, etc.

## Meta

Some Yara rules have a `clamav` meta entry. When this item is true, the build scripts in this repo will include these Yara rules in the ClamAV signature archive stored in `dist`.
