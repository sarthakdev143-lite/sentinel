import std/strutils
let MutexName = "Global\\MicrosoftEdgeUpdateTaskRuntime"
echo "MutexName = '", MutexName, "'  len=", MutexName.len
let localName = MutexName.replace("Global\\", "")
echo "localName = '", localName, "'  len=", localName.len
echo "Same? ", localName == MutexName
