.PHONY: help
help: # Display help for all Makefile commands
	@grep -E '^[a-zA-Z0-9 -]+:.*#'  Makefile | sort | while read -r l; do printf "\033[1;32m$$(echo $$l | cut -f 1 -d':')\033[00m:$$(echo $$l | cut -f 2- -d'#')\n"; done

.PHONY: build-clamav
build-clamav: # Compile all yara rules into a single file - and put all into a flat directory
	pipenv run python scripts/build/clamav.py

.PHONY: build-yara
build-yara: # Compile all yara rules into a single file - and put all into a flat directory
	pipenv run python scripts/build/yara.py

.PHONY: build
build: build-clamav build-yara # Build all rules for all detections

.PHONY: scan
scan: # Scan the file (or all files in the dir) specified by the FILE arg.
	./scripts/tools/scan $(FILE)