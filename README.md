# dareog

ORC meets DWARF.

## Building

Install dependencies:

* meson
* libelf
* [libdwarfw](https://github.com/emersion/libdwarfw)  
  Alternatively, you can use git submodules:
  ```shell
  git submodule init
  git submodule update
  ```

Run these commands:

```shell
meson build
ninja -C build
```

## License

GPLv2

Copyright (c) 2017 Josh Poimboeuf <jpoimboe@redhat.com>
Copyright (c) 2018 emersion
