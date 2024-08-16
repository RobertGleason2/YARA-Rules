rule Yara_Example {
    
    meta: 
        last_updated = "2021-10-15"
        author = "Robert Gleason"
        description = "YARA Rule for the WannaCry Ransomeware"

    strings:
        // Fill out identifying strings and other criteria
        $payload_executable = "tasksche.exe"
        $language = "C++"
        $sus_hex_string = "83 EC ?? 24 14 "
        $PE_magic_byte = "MZ"
        $suspicious_domain = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
        $encryption_api_call = "CryptEncrypt"
        

    condition:
        // Fill out the conditions that must be met to identify the binary
        $PE_magic_byte at 0 and
        ($payload_executable and $language and $encryption_api_call and $suspicious_domain) 
        or 
        $sus_hex_string
}