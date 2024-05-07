# FastPFHook

## Synopsis
FastPFHook is work-in-progress, proof-of-concept project that aims to demonstrate how one can significantly improve the performance of page fault (#PF) based hooking methods. FastPFHook parses and translates assembly instructions from a page containing the assembly instructions of the function that we want to hook and translates them to be executed on a separate page after a #PF exception is triggered and caught by an exception handler. The translation process includes transforming rip-relative instructions into absolute counterparts.

## TODOs

* Multi-threading
* Handling Certain Assembly Instructions

## Credits

* [TsudaKageyu - minhook](https://github.com/TsudaKageyu/minhook/)
* [btbd - smap](https://github.com/btbd/smap)