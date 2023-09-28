rule TestRule : test_rule
{
    meta:
        Author = "MTRNord"
        Description = "Test Rule"
        Action = "Notify"
    strings:
        $test_string = "Test"  ascii nocase

    condition:
        $test_string
}
