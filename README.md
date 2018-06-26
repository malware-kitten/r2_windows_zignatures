### Description
This is a collection of zignatures used for radare

### Method
The method used to generate these is best described here (https://github.com/radare/radare2/issues/7310).

Essentially a .lib file is an AR archive containing \*.obj files, those are iterated over and stored as zignatures.  A deduplication method is run after the zignature is created.

For right now, all zignatures are stored as single JSON files per lib file.  No monolithic Windows pack has been created yet.

The directories that zignatures are ran against
`C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\lib\amd64\`
`C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\lib\arm\`
