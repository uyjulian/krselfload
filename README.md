# Plugin allowing loading of Kirikiri from archive

This plugin allows Kirikiri to be loaded from an archive.

## Building

After cloning submodules, a simple `make` will generate `krselfload.dll`.

## How to use

After `Plugins.link("krselfload.dll");` is used, the plugin will change directory to itself (if it is an XP3 archive) and attempt to load `tvpwin32.exe` using process hollowing. If loading is successful, the process will wait until the new process ends, then exit.

## License

This project is licensed under the MIT license. Please read the `LICENSE` file for more information.
