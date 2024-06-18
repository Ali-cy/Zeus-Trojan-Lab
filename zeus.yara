rule Zeus {
    meta:
        author = "Ali Charty"
        description = "A detection rule against ZeusBankingVersion_26Nov2013"
    strings:
        $file_name = "invoice_2318362983713_823931342io.pdf.exe" ascii
        // Suspected name of functions and DLL functionalities.
        $functions_name_KERNEL32_CreateFileA = "CellrotoCrudeUntohighCols" ascii

        // PE Magic Byte.
        $PE_magic_byte = "MZ"

        // HEX String Function name.
        $hex_string = { 43 61 6D 65 6C 6C 6F 74 6F 43 72 75 64 65 55 6E 74 6F 68 69 67 68 43 6F 6C 73 }
    
    condition:
        $PE_magic_byte at 0 and $file_name
        and $functions_name_KERNEL32_CreateFileA
        or $hex_string
}
