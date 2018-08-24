# How to contribute


## Reporting bugs

If you find a bug in this project, please [open an issue](https://github.com/breard-r/libreauth/issues) and describe the problem. When reporting a bug, please follow the generic [bug reporting recommendations](http://www.chiark.greenend.org.uk/~sgtatham/bugs.html).


## Pull requests

When submitting code, please follow the following guidelines:

- report any remarkable change in the change log ;
- document every publicly accessible item (module, function, …) with [rustdoc](https://doc.rust-lang.org/book/documentation.html) and insert examples ;
- write unit tests that checks your code is working well ;
- for bug-fixes, write unit tests showing the corrected bug ;
- for new features, do not forget to create the C-bindings ;
- yes, unit tests have to be written for C-bindings too ;
- format your code using [rustfmt](https://github.com/rust-lang-nursery/rustfmt) ;
- use [clippy](https://github.com/rust-lang-nursery/rust-clippy) to detect common mistakes ;
- **launch the test suite before submitting your code**, obviously every single test have to pass.
