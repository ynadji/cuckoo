rule jgftmp
{
meta:
	description = "Flagged on thd pdb filepath"
	hash0 = "b082aa539f711d62988b7b7d78bee26c"
strings:
	$string0 = "S:\\kyqAmx\\mpJafkQP\\nTjVqsi\\hWbksmA.pdb"
condition:
	1 of them
}
