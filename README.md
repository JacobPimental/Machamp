# Machamp

<a href="doc/img/machamp.png"><img src="doc/img/machamp.png" border="0" /></a>

Based on the fuzzy hashing mechanism <a href="https://github.com/ANSSI-FR/polichombr/blob/dev/docs/MACHOC_HASH.md">Machoc</a>, Machamp is a fuzzy hashing algorithm based on the *Call Flow Graph* _(CFG)_ of a function. With Machamp there is another layer of abstraction, where the hash for a function is based on the individual hash of each basic block. The purpose of this hash is to match functions to easily *"unstrip"* a binary by renaming functions based on their hash.

## Algorithm

1. Each basic block of a function should be given a number, ordered by address.
2. Each basic block must be translated into a string `NUMBER:j[j];f[f];c[c]`

    * `NUMBER` is the basic block number
    * `j` is the next block's number for when the jump condition is __true__, -1 if not applicable
    * `f` is the next block's number for when the jump condition is __false__, -1 if not applicable
    * `c` is the number of calls made in a block, 0 if none

3. The string is then converted into an md5sum hash and converted to base64
4. The first 6 characters of this hash are taken, this is the hash of that basic block
5. All basic block hashes are combined to form one long hash
6. Another hash is created from the string `[a]:[l]`

    * `a` is the number of arguments the function takes
    * `l` is the number of local variables in the function

7. This hash is then appended onto the end of the hash from step 5, this is the Machamp Hash of the function

## Example
