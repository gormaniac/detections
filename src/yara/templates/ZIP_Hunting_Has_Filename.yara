rule ZIP_Hunting_Has_Filename
{
	meta:
		author = "gormaniac"
		description = "Detect if a Zip file has a given filename"
		date = "2024-03-30"
		version = "1.0.0"

	strings:
		$magic = { 50 4B }

        // Zip file central directory magic followed by <insert filename> 42 bytes later
        $central_dir_entry = { 50 4B 01 02 [42] <insert filename bytes> }

	condition:
		$magic at 0 and $central_dir_entry
}