rule SafeFile_Test_String
{
    meta:
        description = "Test rule that triggers if the file contains the string SafeFileTest123"
        author = "Fatima Jameel"
        severity = "low"

    strings:
        $a = "SafeFileTest123"

    condition:
        $a
}
