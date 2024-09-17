### GENERATE HASH:

-c `<cost>`
-r random cost (up to 31) 
-r -x `<max  random  cost>`
-p `<password  to  hash>`

### MATCH:

-m match
-p `<password  to  match>`
-h `<hash  to  match>`

### EXAMPLE:

bcrypt.exe -p Abc12345! (default cost if not specified is 10)

bcrypt.exe -c 15 -p Abc12345!

bcrypt.exe -r -p Abc12345!

bcrypt.exe -r -x 18 -p Abc12345!

bcrypt.exe -m -p Abc12345! -h '$2a$10$7qL9Z...'

 ### Practical Usage
You can combine it with PowerShell, to hash a large amount of plaintext password stored in a text file.

``$content = Get-Content passwords.txt``
``foreach($pw in $content){.\bcrypt.exe -p $pw}``