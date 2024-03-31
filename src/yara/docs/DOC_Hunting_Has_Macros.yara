rule DOC_Hunting_Has_Macros
{
	meta:
		author = "gormaniac"
		description = "Document file has Macros"
		date = "2024-03-30"
		version = "1.0.0"

		clamav = true

		triage_score = 1
		triage_description = "Detect if a Microsoft document has Macros."

	strings:
		$ooxmlmagic = { 50 4B }
		$docmagic = { D0 CF 11 E0 }

        // Zip file central directory magic followed by "vbaProject.bin" 42 + (3 to 10 bytes) bytes later
		// the variation allows for various file formats to be supported, as the vba bin file is stored in
		// a different folder depending on doc type.
        $vbaproj_central_dir_entry = { 50 4B 01 02 [42] [3-10] 76 62 61 50 72 6f 6a 65 63 74 2e 62 69 6e }

		$doc_root_entry = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 00 } // The OLE doc "Root Entry"
		$docmacros = { 4D 00 61 00 63 00 72 00 6F 00 73 00 } // A MACROS folder in the OLE doc
		$docvba = { 56 00 42 00 41 00 } // A VBA folder in the OLE doc
		$docvba_proj = { 5F 00 56 00 42 00 41 00 5F 00 50 00 52 00 4F 00 4A 00 45 00 43 00 54 00 5F 00 43 00 55 00 52 00 } // A _VBA_PROJECT_CUR folder in the OLE doc

	condition:
		// Look for macros in OOXML docs
		($ooxmlmagic at 0 and $vbaproj_central_dir_entry)
		// Look for macros in OLE docs
		or ($docmagic at 0 and $doc_root_entry and ($docmacros or $docvba or $docvba_proj))
}